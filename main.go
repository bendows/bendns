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
	"github.com/bendows/goredis"

	"github.com/miekg/dns"
)

var serverconfig struct {
	listenIP    string
	nameservers string
	TTL         int
	redisHost   string
	network     string
	localDomain string
	redisPort   string
}

func init() {
	logger.LogOn = true
	flag.StringVar(&serverconfig.listenIP, "dns-ip", "lookup", "The IP address to listen on.")
	flag.StringVar(&serverconfig.nameservers, "nameservers", "8.8.4.4,8.8.8.8", "DNS servers to forward requests to.")
	flag.StringVar(&serverconfig.network, "network", "192.168.0", "The network.")
	flag.IntVar(&serverconfig.TTL, "ttl", 60, "TTL in seconds for authorative records.")
	flag.StringVar(&serverconfig.localDomain, "localDomain", "localdns.co.za", "Authoritave domain.")
	flag.StringVar(&serverconfig.redisHost, "redis-host", "127.0.0.1", "The REDIS-HOST to connect to.")
	flag.StringVar(&serverconfig.redisPort, "redis-port", "6379", "The REDIS-PORT to connect to.")
	goredis.Init(serverconfig.redisHost, serverconfig.redisPort)
}

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

func ForwardAnswer(req *dns.Msg) (ns string, am *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	client := &dns.Client{Net: "udp", SingleInflight: true}
	for _, ns := range strings.Split(serverconfig.nameservers, ",") {
		if r, _, err := client.Exchange(req, ns+":53"); err == nil {
			r.Compress = true
			if r.Rcode == dns.RcodeSuccess {
				return ns, r
			}
			r.SetRcode(req, dns.RcodeServerFailure)
			return ns, r
		}
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
			A: net.ParseIP(serverconfig.listenIP),
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  q.Qclass,
				Ttl:    uint32(serverconfig.TTL),
			},
		})
		break
	case dns.TypeMX:
		m.Answer = append(m.Answer, &dns.MX{
			Preference: 10,
			Mx:         "mail1." + serverconfig.localDomain + ".",
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
			},
		})
		m.Answer = append(m.Answer, &dns.MX{
			Preference: 15,
			Mx:         "mail2." + serverconfig.localDomain + ".",
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
			},
		})
		break
	case dns.TypeNS:
		m.Answer = append(m.Answer, &dns.NS{
			Ns: "ns1." + serverconfig.localDomain + ".",
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
			},
		})
		m.Answer = append(m.Answer, &dns.NS{
			Ns: "ns2." + serverconfig.localDomain + ".",
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
			},
		})
		break
	case dns.TypeSOA:
		m.Answer = append(m.Answer, &dns.SOA{
			Ns:      "ns1." + serverconfig.localDomain + ".",
			Mbox:    "ben." + serverconfig.localDomain + ".",
			Serial:  uint32(time.Now().Unix()),
			Refresh: uint32(serverconfig.TTL),
			Retry:   uint32(serverconfig.TTL),
			Expire:  uint32(serverconfig.TTL),
			Minttl:  uint32(serverconfig.TTL),
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
			},
		})
		break
	case dns.TypePTR:
		// qip := strings.TrimSuffix(q.Name, ".in-addr.arpa.")
		// ip := reverseIP(qip)
		answer := "swan." + serverconfig.localDomain + "."
		logger.Loginfo.Printf("PTR [%s] [%s]\n", q.Name, answer)
		// ptr := ""
		// if goredis.RedisKeyExists("dhcp:ip:"+ip) == 1 {
		// 	ptr = goredis.GetString("dhcp:ip:" + ip)
		// } else {
		// ptr = "yellow"
		// }

		m.Answer = append(m.Answer, &dns.PTR{
			Ptr: answer,
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    uint32(serverconfig.TTL),
			},
		})
	default:
		if q.Qtype == 65 {
			m.Answer = append(m.Answer, &dns.A{
				A: net.ParseIP(serverconfig.listenIP),
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  q.Qclass,
					Ttl:    uint32(serverconfig.TTL),
				},
			})
			break
		}
		m.SetRcode(req, dns.RcodeServerFailure)
		logger.Loginfo.Printf("woooops qtype [%v] qname [%v]\n", q.Qtype, q.Name)
	}
	return m
}

func reverseIP(ip string) string {
	octets := strings.Split(ip, ".")
	reverseoctets := []string{}
	for i := range octets {
		octet := octets[len(octets)-1-i]
		reverseoctets = append(reverseoctets, octet)
	}
	return strings.Join(reverseoctets, ".")
}

func main() {
	flag.Parse()
	if serverconfig.listenIP == "lookup" {
		serverconfig.listenIP = resolveHostIp()
	}
	logger.Loginfo.Printf("[%+v] DNS server running\n", serverconfig)
	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		for _, q := range req.Question {
			if q.Qtype != dns.TypePTR && strings.HasSuffix(q.Name, serverconfig.localDomain+".") {
				m := AuthoritaveAnswer(req, &q)
				w.WriteMsg(m)
				logger.Loginfo.Printf("A [%s] [%d] %s %s\n", w.RemoteAddr(), q.Qtype, serverconfig.listenIP, m.Answer)
				continue
			}
			if q.Qtype == dns.TypePTR && strings.HasSuffix(q.Name, ".in-addr.arpa.") {
				qip := strings.TrimSuffix(q.Name, ".in-addr.arpa.")
				ip := reverseIP(qip)
				if strings.HasPrefix(ip, serverconfig.network) {
					m := AuthoritaveAnswer(req, &q)
					w.WriteMsg(m)
					continue
				}
				ns, m := ForwardAnswer(req)
				w.WriteMsg(m)
				logger.Loginfo.Printf("F [%s] [%d] [%s] %s\n", w.RemoteAddr(), q.Qtype, ns, m.Answer)
				continue
			}
			ns, m := ForwardAnswer(req)
			w.WriteMsg(m)
			logger.Loginfo.Printf("F [%s] [%d] [%s] %s\n", w.RemoteAddr(), q.Qtype, ns, m.Answer)
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

	server := &dns.Server{Addr: serverconfig.listenIP + ":53", Net: "udp", TsigSecret: nil}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to setup server: %v\n", err)
	}
}
