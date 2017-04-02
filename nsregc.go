package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	//	"os/signal"
	"strconv"
	//	"strings"
	//	"syscall"
	"time"
	//	"math/big"

	//	"keydb"
	"encoding/json"
	"io/ioutil"

	//	"encoding/binary"
	//	"encoding/base64"
	//	"crypto/rsa"
	//	"crypto/rand"
	//	"crypto/sha256"

	"crypto"
	"github.com/miekg/dns"
)

const (
	srvname = "_nsregd._tcp"
)

var (
	printf   = flag.Bool("print", false, "print replies")
	conffile = flag.String("conffile", "nsregc.conf", "Config file")
	port     = flag.Int("port", 53, "port number to use")
	tcp      = flag.Bool("tcp", false, "Use TCP for initial SRV query")
	config   Config

	keyrr   *dns.KEY
	privkey crypto.PrivateKey
)

type Config struct {
	Name           string
	KeyFile        string
	PrivateKeyFile string
	Interfaces     []string
}

func sign(m *dns.Msg, name string) *dns.Msg {
	keyrr.Hdr.Name = name

	m.Extra = append(m.Extra, keyrr)

	now := uint32(time.Now().Unix())
	sigrr := new(dns.SIG)
	sigrr.Hdr.Name = "."
	sigrr.Hdr.Rrtype = dns.TypeSIG
	sigrr.Hdr.Class = dns.ClassANY
	sigrr.Algorithm = keyrr.Algorithm
	sigrr.Expiration = now + 300
	sigrr.Inception = now - 300
	sigrr.KeyTag = keyrr.KeyTag()
	sigrr.SignerName = name
	mb, err := sigrr.Sign(privkey.(crypto.Signer), m)

	if err != nil {
		fmt.Println("Unable to sign:" + err.Error())
	}

	msg := new(dns.Msg)
	msg.Unpack(mb)

	return msg
}

func getServer(name string, server string, tcp bool) string {
	c := new(dns.Client)
	if tcp {
		c.Net = "tcp"
	}
	m := new(dns.Msg)
	m.SetQuestion(srvname+"."+name, dns.TypeSRV)
	m.SetEdns0(4096, true)
	r, _, err := c.Exchange(m, server)
	if err != nil {
		return ""
	}
	for _, k := range r.Answer {
		if srv, ok := k.(*dns.SRV); ok {
			return srv.Target + ":" + strconv.Itoa(int(srv.Port))
		}
	}
	return ""
}

func registerZone(zone string, server string) {
	c := new(dns.Client)
	c.Net = "tcp"

	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: false,
			Opcode:           dns.OpcodeUpdate},
		Question: make([]dns.Question, 1),
	}

	name := config.Name + "." + dns.Fqdn(zone)

	m.Question[0] = dns.Question{Name: name,
		Qtype:  dns.TypeA,
		Qclass: uint16(dns.ClassINET)}

	r, _, err := c.Exchange(sign(m, name), server)

	fmt.Println(r)
	if err != nil {
		fmt.Println(err)
	}

}

func main() {
	var (
		zones []string
	)

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

	fi, err := os.Open(config.KeyFile)
	if err != nil {
		log.Panic(err)
	}
	rr, err := dns.ReadRR(fi, config.KeyFile)
	if err != nil {
		log.Panic(err)
	}
	fi.Close()

	var ok bool
	keyrr, ok = rr.(*dns.KEY)
	if !ok {
		log.Panic("No KEY in keyfile")
	}
	fi, err = os.Open(config.PrivateKeyFile)
	if err != nil {
		log.Panic(err)
	}
	privkey, err = keyrr.ReadPrivateKey(fi, config.KeyFile)

	/* borrowed from 'q' utility in dns library examples */
	var nameserver string
	for _, arg := range flag.Args() {
		// If it starts with @ it is a nameserver
		if arg[0] == '@' {
			nameserver = arg
			continue
		}
		zones = append(zones, arg)
	}
	if len(nameserver) == 0 {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		nameserver = "@" + conf.Servers[0]
	}
	nameserver = string([]byte(nameserver)[1:]) // chop off @
	// if the nameserver is from /etc/resolv.conf the [ and ] are already
	// added, thereby breaking net.ParseIP. Check for this and don't
	// fully qualify such a name
	if nameserver[0] == '[' && nameserver[len(nameserver)-1] == ']' {
		nameserver = nameserver[1 : len(nameserver)-1]
	}
	if i := net.ParseIP(nameserver); i != nil {
		nameserver = net.JoinHostPort(nameserver, strconv.Itoa(*port))
	} else {
		nameserver = dns.Fqdn(nameserver) + ":" + strconv.Itoa(*port)
	}

	log.Printf("Using nameserver %s", nameserver)

	for _, zone := range zones {
		server := getServer(zone, nameserver, *tcp)
		if len(server) == 0 {
			log.Printf("No nsregd server found for zone %s", zone)
		} else {
			log.Printf("Found nsregd server %s for zone %s", server, zone)
			registerZone(zone, server)
		}
	}

}
