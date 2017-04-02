package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
//	"strings"
	"syscall"
//	"time"

	"io/ioutil"
	"encoding/json"
//	"keydb"

//	"encoding/binary"
	"encoding/base64"
//	"crypto/rsa"
//	"crypto/rand"
//	"crypto/sha256"

	"github.com/miekg/dns"
//	"github.com/spf13/viper"
)

var (
	printf     = flag.Bool("print", false, "print replies")
	conffile   = flag.String("conffile", "", "Config file")
	config Config
)

type Config struct {
	ListenAddr string
	ListenPort int
	Zones []Zone
}

type Zone struct {
	Name string
	UpstreamNS string
	TSigName string
	TSigSecret string
	Networks []net.IPNet
	AllowAnyNet bool
	KeyDbFile string
	KeyTimeout uint
	keydb *KeyDb
}

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func toKEY(dk *dns.DNSKEY) *dns.KEY {
	k := &dns.KEY{DNSKEY: *dk}
	k.Hdr = *new(dns.RR_Header)
	k.Hdr.Name = dk.Hdr.Name
	k.Hdr.Rrtype = dns.TypeKEY
	k.Hdr.Class = dk.Hdr.Class
	k.Hdr.Ttl = dk.Hdr.Ttl
	k.Hdr.Rdlength = dk.Hdr.Rdlength
	return k
}

func (zone *Zone) validName(name string) bool {
	return dns.CompareDomainName(name, zone.Name) == dns.CountLabel(zone.Name) && dns.CountLabel(name) > dns.CountLabel(zone.Name)
}

func (zone *Zone) verifySig(r *dns.Msg) (name string, success bool) {

	var (
		sigrr *dns.SIG
		keyrr *dns.KEY
	)

	for _, rr := range r.Extra {
		if k, ok := rr.(*dns.KEY); ok {
			if keyrr != nil {
				return
			}
			keyrr = k
		}
		if s, ok := rr.(*dns.SIG); ok {
			if sigrr != nil {
				return
			}
			sigrr = s
		}
	}

	if sigrr == nil {
		return
	}

	name = sigrr.SignerName

	buf, err := r.Pack()
	if err != nil {
		return
	}

	key, ok := zone.keydb.Get(name)
	if ok {
		/* Found existing key, verify sig */
		if key.KeyTag != sigrr.KeyTag {
			log.Printf("Existing key for %s has different keytag than SIG", name)
			return
		}
		log.Printf("Found existing key for %s", name)
		keyrr = new(dns.KEY)
		keyrr.Hdr.Name = name
		keyrr.Hdr.Rrtype = dns.TypeKEY
		keyrr.Flags = key.Flags
		keyrr.Protocol = key.Protocol
		keyrr.Algorithm = key.Algorithm
		keyrr.PublicKey = key.PublicKey

		err := sigrr.Verify(keyrr, buf)
		if err == nil {
			log.Printf("Verified sig for %s", name)
			zone.keydb.Refresh(name)
			return name, true
		} else {
			log.Printf("Failed to verify sig for %s", name)
		}
	} else {
		/* No existing key, keep if in valid dom */
		if !zone.validName(name) {
			log.Printf("Invalid new name %s", name)
			return
		}
		if keyrr == nil {
			log.Printf("No existing key found for %s and no KEY record in query", name)
			return
		}

		err := sigrr.Verify(keyrr, buf)
		if err == nil {
			log.Printf("Verified sig with new key for %s", name)
			key = Key{
				Name: name,
				Flags: keyrr.Flags,
				Protocol: keyrr.Protocol,
				Algorithm: keyrr.Algorithm,
				KeyTag: keyrr.KeyTag(),
				PublicKey: keyrr.PublicKey,}
			if zone.keydb.Add(key) {
				return name, true
			}
		}
	}

	return name, false
}



func (zone *Zone) handleRegd(w dns.ResponseWriter, r *dns.Msg) {

	var (
		name string
		ok bool
	)

	m := new(dns.Msg)
	m.SetReply(r)

	if r.MsgHdr.Opcode == dns.OpcodeQuery && r.Question[0].Qtype == dns.TypeSRV {
		q := r.Question[0]
		rr := &dns.SRV{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSRV,
				Class: dns.ClassINET, Ttl: 0},
			Port: uint16(config.ListenPort),
			Target: dns.Fqdn(config.ListenAddr),
		}
		m.Answer = append(m.Answer, rr)
		goto out
	}

	if r.MsgHdr.Opcode != dns.OpcodeUpdate {
		m.Rcode = dns.RcodeRefused
		goto out
	}

	name, ok = zone.verifySig(r)
	if !ok {
		m.Rcode = dns.RcodeNotAuth
		goto out
	}


	for _, q := range r.Question {
		if q.Name != name {
			m.Rcode = dns.RcodeRefused
			goto out
		}

		switch q.Qtype {
		case dns.TypeA, dns.TypeAAAA, dns.TypeKEY:
			log.Printf("Got %s request", dns.TypeToString[q.Qtype])
		default:
			m.Rcode = dns.RcodeRefused
		}
	}

	if *printf {
		fmt.Printf("%v\n", m.String())
	}

out:
	err := w.WriteMsg(m)
	if err != nil {
		fmt.Printf("error on write: %s\n", err.Error())
	}
}

func serve(addr string, port int) {
	laddr := addr + ":" + strconv.Itoa(port)
	server := &dns.Server{Addr: laddr, Net: "tcp"}
	log.Printf("Starting server on %s (tcp)", laddr)
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("Failed to setup the server: %s\n", err.Error())
	}

}

func main() {
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	data, err := ioutil.ReadFile(*conffile)
	if err != nil {
		log.Print(err)
		return
	}
	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Print(err.Error())
		return
	}

	for _,zone := range config.Zones {
		kdb, err := NewKeyDb(zone.KeyDbFile, zone.KeyTimeout)
		if err != nil {
			return
		}
		log.Printf("Configuring zone %s with db file %s", zone.Name, zone.KeyDbFile)
		zone.keydb = kdb
		defer kdb.Stop()
		dns.HandleFunc(zone.Name, zone.handleRegd)
	}

	go serve(config.ListenAddr, config.ListenPort)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)

}
