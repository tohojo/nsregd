package main

import (
	"flag"
	"fmt"
	"log"
//	"net"
	"os"
	"os/signal"
//	"strconv"
//	"strings"
	"syscall"
//	"time"

//	"keydb"

//	"encoding/binary"
	"encoding/base64"
//	"crypto/rsa"
//	"crypto/rand"
//	"crypto/sha256"

	"github.com/miekg/dns"
)

const dom = "nsregd.example.org."

var (
	printf     = flag.Bool("print", false, "print replies")
	keydbfile  = flag.String("keydb", "", "Filename to store keys")
	keydb *KeyDb
)

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

func verifySig(r *dns.Msg) (name string, success bool) {

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

	name = sigrr.Hdr.Name

	buf, err := r.Pack()
	if err != nil {
		return
	}

	key, ok := keydb.Get(name)
	if ok {
		/* Found existing key, verify sig */
		keyrr = new(dns.KEY)
		keyrr.Hdr.Name = name
		keyrr.Hdr.Rrtype = dns.TypeKEY
		keyrr.Flags = key.Flags
		keyrr.Protocol = key.Protocol
		keyrr.Algorithm = key.Algorithm
		keyrr.PublicKey = key.PublicKey

		err := sigrr.Verify(keyrr, buf)
		if err == nil {
			keydb.Refresh(name)
			return name, true
		}
	} else {
		/* No existing key, keep if in valid dom */
		if dns.CompareDomainName(name, dom) != dns.CountLabel(dom) {
			return
		}
		if keyrr == nil {
			return
		}

		err := sigrr.Verify(keyrr, buf)
		if err == nil {
			key = Key{
				Name: name,
				Flags: keyrr.Flags,
				Protocol: keyrr.Protocol,
				Algorithm: keyrr.Algorithm,
				PublicKey: keyrr.PublicKey}
			if keydb.Add(key) {
				return name, true
			}
		}
	}

	return name, false
}



func handleRegd(w dns.ResponseWriter, r *dns.Msg) {

	var (
		name string
		ok bool
	)

	fmt.Println(r.String())
	m := new(dns.Msg)
	m.SetReply(r)

	if r.MsgHdr.Opcode != dns.OpcodeUpdate {
		m.Rcode = dns.RcodeRefused
		goto out
	}

	name, ok = verifySig(r)
	if !ok {
		m.Rcode = dns.RcodeBadSig
		goto out
	}


	for _, q := range r.Question {
		if q.Name != name {
			m.Rcode = dns.RcodeNotAuth
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

func serve(net, name, secret string) {
	switch name {
	case "":
		server := &dns.Server{Addr: ":8053", Net: net, TsigSecret: nil}
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
		}
	default:
		server := &dns.Server{Addr: ":8053", Net: net, TsigSecret: map[string]string{name: secret}}
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
		}
	}
}

func main() {
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	keydb = NewKeyDb(*keydbfile)

	dns.HandleFunc("example.org.", handleRegd)
	go serve("tcp", "", "")
	go serve("udp", "", "")
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)

/*	keydb := keydb.New("test.json")
	if secret, ok := keydb.Get("test"); ok {
		fmt.Printf("Key for test: %s\n", secret)
	}
	if secret, ok := keydb.Get("test3"); ok {
		fmt.Printf("Key for test3: %s\n", secret)
	}
	if ok := keydb.Add("test", "testing"); ok {
		fmt.Println("Added key for test")
	}
	if ok := keydb.Add("test", "testing"); ok {
		fmt.Println("Added key for test")
	} else {
		fmt.Println("Failed adding key for test")
	}
	if secret, ok := keydb.Get("test"); ok {
		fmt.Printf("Key for test: %s\n", secret)
	}
	if _, ok := keydb.Get("test2"); !ok {
		fmt.Println("No key found for test2")
	}
	keydb.Add("test3", "meep")
/*	time.Sleep(3 * time.Second)
	keydb.Refresh("test")
	time.Sleep(3 * time.Second)
	if secret, ok := keydb.Get("test"); ok {
		fmt.Printf("Key for test: %s\n", secret)
	} else {
		fmt.Println("No key found for test")
	}
*/	//keydb.Stop()
}
