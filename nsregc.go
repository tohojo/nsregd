package main

import (
	"bytes"
	"crypto"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	"encoding/json"
	"io/ioutil"
	"os/signal"

	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
)

const (
	srvname         = "_nsreg._tcp"
	skip_addr_flags = syscall.IFA_F_TEMPORARY | syscall.IFA_F_DEPRECATED
)

var (
	printf   = flag.Bool("print", false, "print replies")
	conffile = flag.String("conffile", "nsregc.conf", "Config file")
	port     = flag.Int("port", 53, "port number to use")
	tcp      = flag.Bool("tcp", false, "Use TCP for initial SRV query")
	keep     = flag.Bool("keep", false, "do not flush entries from upstreams on shutdown")
	config   Config

	keyrr   *dns.KEY
	privkey crypto.PrivateKey
)

type Config struct {
	Name           string
	KeyFile        string
	PrivateKeyFile string
	Interfaces     []string
	ExcludeNets    []string
	MaxTTL         uint32
	excludedNets   []*net.IPNet
}

type Server struct {
	Hostname string
	Zone     string
	Name     string
	cache    Cache
}

type Addr struct {
	IP  net.IP
	Ttl uint32
}

func (a *Addr) toRR(name string) dns.RR {
	if v4 := a.IP.To4(); v4 != nil {
		return &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: getTTL(a.Ttl)},
			A: a.IP}
	} else {
		return &dns.AAAA{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA,
				Class: dns.ClassINET, Ttl: getTTL(a.Ttl)},
			AAAA: a.IP}
	}
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

func getServer(zone string, server string, tcp bool) (*Server, bool) {
	c := new(dns.Client)
	if tcp {
		c.Net = "tcp"
	}
	m := new(dns.Msg)
	m.SetQuestion(srvname+"."+zone, dns.TypeSRV)
	m.SetEdns0(4096, true)
	r, _, err := c.Exchange(m, server)
	if err != nil {
		return nil, false
	}
	for _, k := range r.Answer {
		if srv, ok := k.(*dns.SRV); ok {
			serv := &Server{Zone: dns.Fqdn(zone),
				Name:     config.Name + "." + dns.Fqdn(zone),
				Hostname: srv.Target + ":" + strconv.Itoa(int(srv.Port))}
			serv.cache.ExpireCallback = serv.Refresh
			serv.cache.MaxTTL = config.MaxTTL
			serv.cache.Init()
			return serv, true
		}
	}
	return nil, false
}

func excludeIP(ip net.IP) bool {

	for _, net := range config.excludedNets {
		if net.Contains(ip) {
			return true
		}
	}

	return false
}

func getAddrs(ifname string) ([]Addr, error) {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		/* netlink failed - fall back to net library */
		iface, err := net.InterfaceByName(ifname)
		if err != nil {
			log.Printf("Couldn't find interface %s: %s\n", link, err)
			return nil, err
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		res := make([]Addr, 0, len(addrs))
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				res = append(res, Addr{IP: v.IP})
			case *net.IPAddr:
				res = append(res, Addr{IP: v.IP})
			}
		}
		return res, nil
	}

	addrs, err := netlink.AddrList(link, 0)
	if err != nil {
		return nil, err
	}
	res := make([]Addr, 0, len(addrs))
	for _, addr := range addrs {
		if addr.Flags&skip_addr_flags == 0 && !excludeIP(addr.IPNet.IP) {
			res = append(res, Addr{IP: addr.IPNet.IP,
				Ttl: uint32(addr.ValidLft)})
		}
	}
	return res, nil
}

func getTTL(ttl uint32) uint32 {
	if ttl == 0 || ttl > config.MaxTTL {
		return config.MaxTTL
	}
	return ttl
}

func (s *Server) run() {
	m := new(dns.Msg)
	m.SetUpdate(s.Zone)

	for _, ifname := range config.Interfaces {
		addrs, err := getAddrs(ifname)
		if err != nil {
			log.Printf("Unable to get addresses for interface %s", ifname)
			continue
		}

		rr := make([]dns.RR, len(addrs))
		for i, a := range addrs {
			rr[i] = a.toRR(s.Name)
		}
		m.Insert(rr)

	}

	s.send(m)

}

func (s *Server) send(m *dns.Msg) bool {
	c := new(dns.Client)
	c.Net = "tcp"

	log.Printf("Attempting to register %d addresses for name %s",
		len(m.Ns), s.Name)

	r, _, err := c.Exchange(sign(m, s.Name), s.Hostname)

	if *printf {
		fmt.Println(r)
	}
	if err != nil {
		log.Fatal(err)
		return false
	} else if r.Rcode != dns.RcodeSuccess {
		log.Printf("Registration failed with code: %s", dns.RcodeToString[r.Rcode])
		return false
	} else {
		log.Printf("Successfully registered %d addresses for name %s",
			len(r.Answer), s.Name)

		for _, rr := range r.Answer {
			switch rr.Header().Rrtype {
			case dns.TypeA, dns.TypeAAAA:
				// refresh at half the expire time to be safe
				rr.Header().Ttl /= 2
				if rr.Header().Ttl > 0 {
					s.cache.Add(rr)
				}
			}
		}

		return true
	}

}

func (s *Server) Refresh(rr []dns.RR) bool {
	m := new(dns.Msg)
	m.SetUpdate(s.Zone)

	// When entries expire we check if the address still exists on one of
	// the configured interfaces, and use the current expiry time for the
	// new TTL
	for _, ifname := range config.Interfaces {
		addrs, err := getAddrs(ifname)
		if err != nil {
			log.Printf("Unable to get addresses for interface %s", ifname)
			continue
		}

		for _, a := range addrs {

			for _, r := range rr {
				var ip net.IP
				switch r.Header().Rrtype {
				case dns.TypeA:
					ip = r.(*dns.A).A
				case dns.TypeAAAA:
					ip = r.(*dns.AAAA).AAAA
				}
				if bytes.Compare(ip, a.IP) == 0 {
					log.Printf("Refreshing record for IP %s", ip)
					r.Header().Ttl = getTTL(a.Ttl)
					m.Insert([]dns.RR{r})
				}
			}
		}
	}

	return s.send(m)
}

func (s *Server) Remove() {
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

	for _, n := range config.ExcludeNets {
		_, net, err := net.ParseCIDR(n)
		if err != nil {
			log.Panic(err)
		}
		config.excludedNets = append(config.excludedNets, net)
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
		zones = append(zones, dns.Fqdn(arg))
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
		server, ok := getServer(zone, nameserver, *tcp)
		if !ok {
			log.Printf("No nsregd server found for zone %s", zone)
		} else {
			log.Printf("Found nsregd server %s for zone %s", server.Hostname, zone)
			if !*keep {
				defer server.Remove()
			}
			go server.run()
		}
	}

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}
