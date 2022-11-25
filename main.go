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

	"github.com/miekg/dns"
)

var (
	nameservers = flag.String("nameservers", "8.8.8.8,8.8.4.4", "nameservers for forwarding")
)

func main() {
	flag.Parse()
	// log.Printf("Serving %s->%s and forwarding rest to %s\n", *domain, *domainIP, *nameservers)
	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)

		for _, q := range req.Question {
			switch q.Qtype {
			case dns.TypeANY, dns.TypeA, dns.TypeAAAA:
				m.Authoritative = true
				log.Printf("request %v is A question\n", req.Question)
				m.Answer = append(m.Answer, &dns.A{
					A: net.ParseIP("1.2.3.4"),
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  q.Qclass,
						Ttl:    0,
					},
				})
				w.WriteMsg(m)
				return
			case dns.TypeMX:
				m.Authoritative = true
				log.Printf("request %v is MX question\n", req.Question)
				m.Answer = append(m.Answer, &dns.MX{
					Preference: 10,
					Mx:         "mail.ben.co.za.",
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeMX,
						Class:  dns.ClassINET,
					},
				})
				m.Answer = append(m.Answer, &dns.MX{
					Preference: 15,
					Mx:         "mail2.ben.co.za.",
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeMX,
						Class:  dns.ClassINET,
					},
				})
				w.WriteMsg(m)
				return
			case dns.TypeNS:
				m.Authoritative = true
				log.Printf("request %v is NS question\n", req.Question)
				m.Answer = append(m.Answer, &dns.NS{
					Ns: "ns1.ben.co.za.",
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
					},
				})
				m.Answer = append(m.Answer, &dns.NS{
					Ns: "ns2.ben.co.za.",
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
					},
				})
				w.WriteMsg(m)
				return
			default:
				break
				// case dns.TypeSOA:
				// 	m.Authoritative = true
				// 	log.Printf("request %v is SOA question\n", req.Question)
				// 	break
			}
		}
		log.Printf("forwarding query\n")
		client := &dns.Client{Net: "udp", SingleInflight: true}
		for _, ns := range strings.Split(*nameservers, ",") {
			if r, _, err := client.Exchange(req, ns+":53"); err == nil {
				if r.Rcode == dns.RcodeSuccess {
					r.Compress = true
					w.WriteMsg(r)
					for _, a := range r.Answer {
						log.Printf("Answer from %s: %v\n", ns, a)
					}
					return
				}
			}
		}
		log.Println("failure to forward request")
		m.SetRcode(req, dns.RcodeServerFailure)
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

	server := &dns.Server{Addr: "127.0.0.1:53", Net: "udp", TsigSecret: nil}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to setup server: %v\n", err)
	}
}
