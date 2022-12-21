package main

// Inspired by https://github.com/tianon/rawdns
// https://github.com/tianon/rawdns/blob/b31e358f1c05f89af77adc75c7fde0568002efa8/cmd/rawdns/forwarding.go#L18
import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	logger "github.com/bendows/gologger"

	"github.com/miekg/dns"
)

var (
	nameservers = flag.String("nameservers", "8.8.8.8,8.8.4.4", "nameservers for forwarding")
	listenIP    = flag.String("serverip", "lookup", "IP address to listen on")
)

func resolveHostIp() string {
	netInterfaceAddresses, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, netInterfaceAddress := range netInterfaceAddresses {
		networkIp, ok := netInterfaceAddress.(*net.IPNet)
		if ok && !networkIp.IP.IsLoopback() && networkIp.IP.To4() != nil {
			ip := networkIp.IP.String()
			return ip
		}
	}
	return ""
}

func ForwardAnswer(req *dns.Msg) (string, *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	client := &dns.Client{Net: "udp", SingleInflight: true}
	for _, ns := range strings.Split(*nameservers, ",") {
		if r, _, err := client.Exchange(req, ns+":53"); err == nil {
			r.Compress = true
			if r.Rcode == dns.RcodeSuccess {
				return ns, r
			}
			r.SetRcode(req, dns.RcodeServerFailure)
			return ns, r
		}
		return ns, m
	}
	return "", m
}

func AuthoritaveAnswer(req *dns.Msg, q *dns.Question) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	switch q.Qtype {
	case dns.TypeANY, dns.TypeA, dns.TypeAAAA:
		m.Answer = append(m.Answer, &dns.A{
			A: net.ParseIP(*listenIP),
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  q.Qclass,
				Ttl:    0,
			},
		})
		break
	case dns.TypeMX:
		m.Answer = append(m.Answer, &dns.MX{
			Preference: 10,
			Mx:         "mail1.fblks.io.",
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
			},
		})
		m.Answer = append(m.Answer, &dns.MX{
			Preference: 15,
			Mx:         "mail2.fblks.io.",
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
			},
		})
		break
	case dns.TypeNS:
		m.Answer = append(m.Answer, &dns.NS{
			Ns: "ns1.fblks.io.",
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
			},
		})
		m.Answer = append(m.Answer, &dns.NS{
			Ns: "ns2.fblks.io.",
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
			},
		})
		break
	case dns.TypeSOA:
		m.Answer = append(m.Answer, &dns.SOA{
			Ns:      "ns.fblks.io.",
			Mbox:    "ben.fblks.io.",
			Serial:  uint32(time.Now().Unix()),
			Refresh: uint32(60),
			Retry:   uint32(60),
			Expire:  uint32(60),
			Minttl:  uint32(60),
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
			},
		})
		break
	case dns.TypePTR:
		m.Answer = append(m.Answer, &dns.PTR{
			Ptr: "ns.fblks.io.",
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
			},
		})
		break
	default:
		m.SetRcode(req, dns.RcodeServerFailure)
		logger.Loginfo.Println("woooops")
	}
	return m
}

func main() {
	logger.LogOn = true
	flag.Parse()
	if *listenIP == "lookup" {
		*listenIP = resolveHostIp()
	}
	logger.Loginfo.Printf("Serving DNS on %s forwarding some requests to %s\n", *listenIP, *nameservers)
	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		for _, q := range req.Question {
			if strings.HasSuffix(q.Name, "fblks.io.") {
				m := AuthoritaveAnswer(req, &q)
				w.WriteMsg(m)
				logger.Loginfo.Printf("A [%s] [%d] %s %s\n", w.RemoteAddr(), q.Qtype, *listenIP, m.Answer)
				return //is this correct?
			}
			if q.Qtype == dns.TypePTR {
				m := AuthoritaveAnswer(req, &q)
				w.WriteMsg(m)
				logger.Loginfo.Printf("A [%s] [%d] %s %s\n", w.RemoteAddr(), q.Qtype, *listenIP, m.Answer)
				return //is this correct?
			}
			ns, m := ForwardAnswer(req)
			w.WriteMsg(m)
			logger.Loginfo.Printf("F [%s] [%d] [%s] %s\n", w.RemoteAddr(), q.Qtype, ns, m.Answer)
			return //is this correct?
		}
	})

	go func() {
		sig := make(chan os.Signal)
		signal.Notify(sig, os.Interrupt, os.Kill)
		for {
			select {
			case s := <-sig:
				log.Fatalf("fatal: signal %s received\n", s)
			}
		}
	}()

	server := &dns.Server{Addr: *listenIP + ":53", Net: "udp", TsigSecret: nil}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to setup server: %v\n", err)
	}
}
