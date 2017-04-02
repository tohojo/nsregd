package nsregc

import (
	"flag"
	"fmt"
	"log"
//	"net"
	"os"
//	"os/signal"
	"runtime/pprof"
	"strconv"
//	"strings"
//	"syscall"
//	"time"
	"math/big"

//	"keydb"

//	"encoding/binary"
	"encoding/base64"
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha256"

//	"crypto"
	"github.com/miekg/dns"
)

const dom = "nsregd.example.org."

var (
	cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	printf     = flag.Bool("print", false, "print replies")
	compress   = flag.Bool("compress", false, "compress replies")
	tsig       = flag.String("tsig", "", "use MD5 hmac tsig: keyname:base64")
	hostname   = flag.String("host", "localhost", "DNS server hostname")
	secret     = flag.String("secret", "", "Secret")
	port       = flag.Int("port", 53, "Port number")
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

func publicKeyRSA(k *dns.DNSKEY) *rsa.PublicKey {
	keybuf, err := fromBase64([]byte(k.PublicKey))
	if err != nil {
		return nil
	}

	// RFC 2537/3110, section 2. RSA Public KEY Resource Records
	// Length is in the 0th byte, unless its zero, then it
	// it in bytes 1 and 2 and its a 16 bit number
	explen := uint16(keybuf[0])
	keyoff := 1
	if explen == 0 {
		explen = uint16(keybuf[1])<<8 | uint16(keybuf[2])
		keyoff = 3
	}
	pubkey := new(rsa.PublicKey)

	pubkey.N = big.NewInt(0)
	shift := uint64((explen - 1) * 8)
	expo := uint64(0)
	for i := int(explen - 1); i > 0; i-- {
		expo += uint64(keybuf[keyoff+i]) << shift
		shift -= 8
	}
	// Remainder
	expo += uint64(keybuf[keyoff])
	if expo > 2<<31 {
		// Larger expo than supported.
		// println("dns: F5 primes (or larger) are not supported")
		return nil
	}
	pubkey.E = int(expo)

	pubkey.N.SetBytes(keybuf[keyoff+int(explen):])
	return pubkey
}




func main() {
//	var name, secret string
	var err error
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	domain := flag.Arg(0)
/*	if *tsig != "" {
		a := strings.SplitN(*tsig, ":", 2)
		name, secret = dns.Fqdn(a[0]), a[1] // fqdn the name, which everybody forgets...
	}*/
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	nameserver := dns.Fqdn(*hostname) + ":" + strconv.Itoa(*port)

	c := new(dns.Client)
	c.Net = "tcp"
	
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetUDPSize(dns.DefaultMsgSize)

	m := &dns.Msg{
	MsgHdr: dns.MsgHdr{
		RecursionDesired: false,
		Opcode: dns.OpcodeQuery,
	},
		Question: make([]dns.Question, 1),
	}

	m.Question[0] = dns.Question{Name: dns.Fqdn(domain),
		Qtype: dns.TypeKEY,
		Qclass: uint16(dns.ClassINET)}

	r, _, err := c.Exchange(m, nameserver)


	switch err {
	case nil:
		fmt.Println(r.String())
	default:
		fmt.Println(err.Error())
		return
	}

	rr := r.Answer[0]
	if t, ok := rr.(*dns.KEY); ok {
		pk := publicKeyRSA(&t.DNSKEY)
		encsec, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pk,
			[]byte(*secret), nil)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		m = &dns.Msg{
			MsgHdr: dns.MsgHdr{
				RecursionDesired: false,
				Opcode: dns.OpcodeQuery,
			},
			Question: make([]dns.Question, 1),
		}

		fmt.Println(encsec)

		m.Question[0] = dns.Question{Name: dns.Fqdn(domain),
			Qtype: dns.TypeTKEY,
			Qclass: uint16(dns.ClassINET)}

		b64 := base64.StdEncoding.EncodeToString(encsec)
		m.Extra = append(m.Extra, &dns.TKEY{
			Hdr: dns.RR_Header{Name: dom, Rrtype: dns.TypeTKEY,
				Class: dns.ClassINET, Ttl: 0},
			Algorithm: dns.Fqdn(domain),
			Mode: 4,
			KeySize: uint16(len(b64)),
			Key: b64,
		})
		m.Extra = append(m.Extra, rr)
		m.Extra = append(m.Extra, o)

		fmt.Printf("%d: %s\n", m.Len(), m.String())

		r, _, err := c.Exchange(m, nameserver)
		switch err {
		case nil:
			fmt.Println(r.String())
		default:
			fmt.Println(err.Error())
			return
		}
	}

}
