package main

import (
	"flag"
	"fmt"
//	"log"
//	"net"
//	"os"
//	"os/signal"
	"strconv"
//	"strings"
//	"syscall"
	"time"
//	"math/big"

//	"keydb"

//	"encoding/binary"
	"encoding/base64"
//	"crypto/rsa"
//	"crypto/rand"
//	"crypto/sha256"

	"crypto"
	"github.com/miekg/dns"
)

const dom = "nsregd.example.org."

var (
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

	nameserver := dns.Fqdn(*hostname) + ":" + strconv.Itoa(*port)

	c := new(dns.Client)
	c.Net = "tcp"

	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetUDPSize(dns.DefaultMsgSize)

	keyrr := new(dns.KEY)
	keyrr.Hdr.Name = domain
	keyrr.Hdr.Rrtype = dns.TypeKEY
	keyrr.Hdr.Class = dns.ClassINET
	keyrr.Algorithm = dns.RSASHA256

	pk, err := keyrr.Generate(2048)

	fmt.Println(keyrr)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	m := &dns.Msg{
	MsgHdr: dns.MsgHdr{
		RecursionDesired: false,
		Opcode: dns.OpcodeUpdate,
	},
		Question: make([]dns.Question, 1),
		Extra: make([]dns.RR, 1),
	}

	m.Question[0] = dns.Question{Name: dns.Fqdn(domain),
		Qtype: dns.TypeA,
		Qclass: uint16(dns.ClassINET)}

	m.Extra[0] = keyrr

	now := uint32(time.Now().Unix())
	sigrr := new(dns.SIG)
	sigrr.Hdr.Name = "."
	sigrr.Hdr.Rrtype = dns.TypeSIG
	sigrr.Hdr.Class = dns.ClassANY
	sigrr.Algorithm = keyrr.Algorithm
	sigrr.Expiration = now + 300
	sigrr.Inception = now - 300
	sigrr.KeyTag = keyrr.KeyTag()
	sigrr.SignerName = keyrr.Hdr.Name
	mb, err := sigrr.Sign(pk.(crypto.Signer), m)

	if err != nil {
		fmt.Println(err.Error())
	}

	msg := new(dns.Msg)
	msg.Unpack(mb)


	fmt.Println(msg)
	r, _, err := c.Exchange(msg, nameserver)



	switch err {
	case nil:
		fmt.Println(r.String())
	default:
		fmt.Println(err.Error())
		return
	}

}
