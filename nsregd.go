package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
	"time"

//	"keydb"

//	"encoding/binary"
	"encoding/base64"
	"crypto/rsa"
	"crypto/rand"
//	"crypto/sha256"

	"crypto"
	"github.com/miekg/dns"
)

const dom = "nsregd.example.org."

var (
	cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	printf     = flag.Bool("print", false, "print replies")
	compress   = flag.Bool("compress", false, "compress replies")
	tsig       = flag.String("tsig", "", "use MD5 hmac tsig: keyname:base64")
	keyrr      = dns.DNSKEY{
		Hdr: dns.RR_Header{Name: dom, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 0},
		Protocol: 3,
		Algorithm: dns.RSASHA256}
	privkey crypto.PrivateKey
)

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func handleKeyReg(w dns.ResponseWriter, r *dns.Msg, m *dns.Msg) {
	var (
		key *dns.KEY
		tkey *dns.TKEY
	)

	for _, rr := range r.Extra {
		if k, ok := rr.(*dns.KEY); ok {
			if key != nil {
				m.Rcode = dns.RcodeFormatError
				return
			}
			key = k
		}
		if t, ok := rr.(*dns.TKEY); ok {
			if tkey != nil {
				m.Rcode = dns.RcodeFormatError
				return
			}
			tkey = t
		}
	}

	if key == nil || tkey == nil {
		m.Rcode = dns.RcodeFormatError
		return
	}

	opts := rsa.OAEPOptions{Hash: crypto.SHA256}
	pk := privkey.(rsa.PrivateKey)
	encbuf, err := fromBase64([]byte(tkey.Key))
	if err != nil {
		fmt.Println("Base64 decode error: %s", err.Error())
		m.Rcode = dns.RcodeFormatError
		return
	}
	deckey, err := pk.Decrypt(rand.Reader, encbuf, opts)
	if err != nil {
		fmt.Println("Decrypt error: %s", err.Error())
		m.Rcode = dns.RcodeFormatError
		return
	}

	fmt.Println("Got decrypted key: %s", base64.StdEncoding.EncodeToString(deckey))

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



func handleRegd(w dns.ResponseWriter, r *dns.Msg) {
	/*var (
		rr dns.RR
		addr net.IP
	)*/
	m := new(dns.Msg)
	m.SetReply(r)


	switch r.Question[0].Qtype {
	case dns.TypeTKEY:
		handleKeyReg(w, r, m)
	case dns.TypeKEY:
		log.Println("Got KEY request")
		if m.Question[0].Name == dom {
			m.Answer = append(m.Answer, toKEY(&keyrr))
		} else {
			m.Rcode = dns.RcodeNameError
		}
	}

	if *printf {
		fmt.Printf("%v\n", m.String())
	}
	err := w.WriteMsg(m)
	if err != nil {
		fmt.Printf("error on write: %s\n", err.Error())
	}
}

func handleReflect(w dns.ResponseWriter, r *dns.Msg) {
	var (
		v4  bool
		rr  dns.RR
		str string
		a   net.IP
	)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = *compress
	if ip, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		str = "Port: " + strconv.Itoa(ip.Port) + " (udp)"
		a = ip.IP
		v4 = a.To4() != nil
	}
	if ip, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		str = "Port: " + strconv.Itoa(ip.Port) + " (tcp)"
		a = ip.IP
		v4 = a.To4() != nil
	}

	if v4 {
		rr = &dns.A{
			Hdr: dns.RR_Header{Name: dom, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
			A:   a.To4(),
		}
	} else {
		rr = &dns.AAAA{
			Hdr:  dns.RR_Header{Name: dom, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
			AAAA: a,
		}
	}

	t := &dns.TXT{
		Hdr: dns.RR_Header{Name: dom, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: []string{str},
	}

	switch r.Question[0].Qtype {
	case dns.TypeTXT:
		m.Answer = append(m.Answer, t)
		m.Extra = append(m.Extra, rr)
	default:
		fallthrough
	case dns.TypeAAAA, dns.TypeA:
		m.Answer = append(m.Answer, rr)
		m.Extra = append(m.Extra, t)
	case dns.TypeAXFR, dns.TypeIXFR:
		c := make(chan *dns.Envelope)
		tr := new(dns.Transfer)
		defer close(c)
		if err := tr.Out(w, r, c); err != nil {
			return
		}
		soa, _ := dns.NewRR(`whoami.miek.nl. 0 IN SOA linode.atoom.net. miek.miek.nl. 2009032802 21600 7200 604800 3600`)
		c <- &dns.Envelope{RR: []dns.RR{soa, t, rr, soa}}
		w.Hijack()
		// w.Close() // Client closes connection
		return
	}

	if r.IsTsig() != nil {
		if w.TsigStatus() == nil {
			m.SetTsig(r.Extra[len(r.Extra)-1].(*dns.TSIG).Hdr.Name, dns.HmacMD5, 300, time.Now().Unix())
		} else {
			println("Status", w.TsigStatus().Error())
		}
	}
	if *printf {
		fmt.Printf("%v\n", m.String())
	}
	// set TC when question is tc.miek.nl.
	if m.Question[0].Name == "tc.miek.nl." {
		m.Truncated = true
		// send half a message
		buf, _ := m.Pack()
		w.Write(buf[:len(buf)/2])
		return
	}
	w.WriteMsg(m)
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
	var name, secret string
	var err error
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()
	if *tsig != "" {
		a := strings.SplitN(*tsig, ":", 2)
		name, secret = dns.Fqdn(a[0]), a[1] // fqdn the name, which everybody forgets...
	}
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	privkey, err = keyrr.Generate(2048)
	if err != nil {
		log.Fatal(err)
	}

	dns.HandleFunc("example.org.", handleRegd)
	go serve("tcp", name, secret)
	go serve("udp", name, secret)
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
