// Author:   Toke Høiland-Jørgensen (toke@toke.dk)
// Date:     13 Apr 2017
// Copyright (c) 2017, Toke Høiland-Jørgensen
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"crypto"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"crypto/ecdsa"
	"encoding/base64"
	"os/signal"
	"path/filepath"

	"github.com/miekg/dns"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/vishvananda/netlink"
)

const (
	srv_prefix      = "_nsreg._tcp"
	discover_prefix = "r._dns-sd._udp"
	skip_addr_flags = syscall.IFA_F_TEMPORARY | syscall.IFA_F_DEPRECATED
)

var (
	printf *bool
	config Config

	keyrr   *dns.KEY
	privkey crypto.PrivateKey

	discover_domains = []string{"local.", "home.arpa."}

	retry_time = uint32(1)
)

type Config struct {
	Name           string        `mapstructure:"name"`
	Zones          []string      `mapstructure:"zones"`
	KeyFile        string        `mapstructure:"key-file"`
	PrivateKeyFile string        `mapstructure:"private-key-file"`
	KeyTTL         time.Duration `mapstructure:"key-ttl"`
	AddrTTL        time.Duration `mapstructure:"addr-ttl"`
	Timeout        time.Duration `mapstructure:"dns-timeout"`
	Interfaces     []string      `mapstructure:"interfaces"`
	excludedNets   []*net.IPNet
	extraAddrs     []*net.IPNet
}

type Server struct {
	Hostname string
	Zone     string
	Name     string
	cache    Cache
	nldone   chan struct{}
	closing  bool
	finished chan bool
}

type Addr struct {
	IP  *net.IPNet
	Ttl uint32
}

func (a *Addr) toRR(name string) dns.RR {
	if v4 := a.IP.IP.To4(); v4 != nil {
		return &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: getTTL(a.Ttl)},
			A: a.IP.IP}
	} else {
		return &dns.AAAA{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA,
				Class: dns.ClassINET, Ttl: getTTL(a.Ttl)},
			AAAA: a.IP.IP}
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
		log.Printf("Unable to sign: %s", err)
	}

	// Sign works on the bytestring, so we have to unpack the message after
	// it has been signed
	msg := new(dns.Msg)
	msg.Unpack(mb)

	return msg
}

func getServer(zone string, server string, tcp bool) (*Server, bool) {
	c := new(dns.Client)
	if tcp {
		c.Net = "tcp"
	}
	c.Timeout = config.Timeout

	// Try to find a SRV record for the zone
	m := new(dns.Msg)
	m.SetQuestion(srv_prefix+"."+zone, dns.TypeSRV)
	m.SetEdns0(4096, true)
	r, _, err := c.Exchange(m, server)
	if err != nil {
		log.Printf("Error while getting nsregd server name: %s", err)
		return nil, false
	}
	if *printf {
		fmt.Printf("%s\n", r)
	}
	for _, k := range r.Answer {
		if srv, ok := k.(*dns.SRV); ok {
			serv := &Server{Zone: zone,
				Name:     config.Name + "." + zone,
				Hostname: srv.Target + ":" + strconv.Itoa(int(srv.Port)),
				nldone:   make(chan struct{})}
			serv.cache.ExpireCallback = serv.Refresh
			serv.cache.MaxTTL = uint32(config.AddrTTL.Seconds())
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

func getAddrsBuiltin() ([]Addr, error) {

	var (
		addrs []net.Addr
		err   error
	)

	if len(config.Interfaces) > 0 {
		addrs = make([]net.Addr, 0)
		for _, ifname := range config.Interfaces {
			iface, err := net.InterfaceByName(ifname)
			if err != nil {
				log.Printf("Couldn't find interface %s: %s\n", ifname, err)
				continue
			}
			if a, err := iface.Addrs(); err == nil {
				addrs = append(addrs, a...)
			} else {
				log.Printf("Couldn't get addrs for interface %s: %s\n",
					ifname, err)
				continue
			}
		}
	} else {
		addrs, err = net.InterfaceAddrs()
	}
	if err != nil {
		return nil, err
	}

	res := make([]Addr, 0, len(addrs))
	for _, a := range addrs {
		var addr Addr
		switch v := a.(type) {
		case *net.IPNet:
			addr = Addr{IP: v}
		case *net.IPAddr:
			addr = Addr{IP: &net.IPNet{IP: v.IP}}
		}
		if !excludeIP(addr.IP.IP) {
			res = append(res, addr)
		}
	}
	for _, addr := range config.extraAddrs {
		res = append(res, Addr{IP: addr})
	}
	return res, nil
}

func getAddrs() ([]Addr, error) {
	var (
		addrs []netlink.Addr
		err   error
	)

	// If there are interfaces configured, only get the addresses from
	// those.
	if len(config.Interfaces) > 0 {
		addrs = make([]netlink.Addr, 0)
		for _, ifname := range config.Interfaces {
			var link netlink.Link
			if link, err = netlink.LinkByName(ifname); err != nil {
				log.Printf("Unable to find link %s: %s", ifname, err)
				continue
			}
			if a, err := netlink.AddrList(link, 0); err == nil {
				addrs = append(addrs, a...)
			} else {
				log.Printf("Unable to get addresses for link %s: %s",
					ifname, err)
				continue
			}
		}
	} else {
		// No interfaces configured, get all addresses on the system
		addrs, err = netlink.AddrList(nil, 0)
	}
	if err != nil {
		// Netlink failed; fall back to Go's net module
		return getAddrsBuiltin()
	}
	res := make([]Addr, 0, len(addrs)+len(config.extraAddrs))
	for _, addr := range addrs {
		if addr.Flags&skip_addr_flags == 0 && !excludeIP(addr.IPNet.IP) {
			res = append(res, Addr{IP: addr.IPNet,
				Ttl: uint32(addr.ValidLft)})
		}
	}
	for _, addr := range config.extraAddrs {
		res = append(res, Addr{IP: addr})
	}
	return res, nil
}

func getTTL(ttl uint32) uint32 {
	if ttl == 0 || ttl > uint32(config.AddrTTL.Seconds()) {
		return uint32(config.AddrTTL.Seconds())
	}
	return ttl
}

func (s *Server) run() {
	go func() {
		nlchan := make(chan netlink.AddrUpdate)

		err := netlink.AddrSubscribe(nlchan, s.nldone)
		if err != nil {
			log.Printf("Unable to subscribe to netlink address updates: %s", err)
			return
		}

		for upd := range nlchan {
			lnk, err := netlink.LinkByIndex(upd.LinkIndex)
			if err != nil {
				continue
			}
			ifname := lnk.Attrs().Name
			if len(config.Interfaces) > 0 && !stringInSlice(ifname, config.Interfaces) {
				continue
			}

			if upd.Flags&skip_addr_flags != 0 || excludeIP(upd.LinkAddress.IP) {
				continue
			}

			a := Addr{IP: &upd.LinkAddress, Ttl: uint32(upd.ValidLft)}
			rr := a.toRR(s.Name)
			if upd.NewAddr {
				if s.cache.Check(rr) {
					continue
				}
				log.Printf("New address %s on interface %s",
					upd.LinkAddress.IP, ifname)
				m := new(dns.Msg)
				m.SetUpdate(s.Zone)

				m.Insert([]dns.RR{rr})
				s.send(m)
			} else {
				log.Printf("Lost address %s on interface %s",
					upd.LinkAddress.IP, ifname)
				m := new(dns.Msg)
				m.SetUpdate(s.Zone)

				m.Remove([]dns.RR{rr})
				s.send(m)

				s.cache.Remove(rr)
			}

		}
	}()

	// Send an initial update with the addresses currently configured. The
	// netlink subscription and the refresh logic will take care of the
	// rest.
	m := new(dns.Msg)
	m.SetUpdate(s.Zone)

	addrs, err := getAddrs()
	if err != nil {
		s.Stop()
		return
	}

	rr := make([]dns.RR, len(addrs))
	for i, a := range addrs {
		log.Printf("Registering address: %s", a.IP.IP)
		rr[i] = a.toRR(s.Name)
	}
	m.Insert(rr)

	s.send(m)

}

func getMessage(m *dns.Msg) string {
	// The server may return a human-readable error message as a TXT record
	// in the Additional section. Try to find that.
	if m == nil || len(m.Extra) == 0 || m.Extra[0].Header().Rrtype != dns.TypeTXT {
		return "(unknown)"
	}
	txt := m.Extra[0].(*dns.TXT)
	if len(txt.Txt) == 0 {
		return "(unknown)"
	}
	return txt.Txt[0]
}

func (s *Server) send(m *dns.Msg) bool {
	c := new(dns.Client)
	c.Net = "tcp"
	c.Timeout = config.Timeout

	log.Printf("Sending update with %d addresses for name %s",
		len(m.Ns), s.Name)

	r, _, err := c.Exchange(sign(m, s.Name), s.Hostname)

	if *printf {
		fmt.Println(r)
	}

	if err != nil || r.Rcode == dns.RcodeServerFailure {
		// Send errors and ServerFailure errors are transient, so retry
		// again in a bit
		if err != nil {
			log.Printf("Network error while sending update: %s", err)
		} else {
			log.Printf("Server signaled error: %s", getMessage(r))
		}

		if !s.closing {
			log.Printf("Queueing RRs for retry in %d seconds", retry_time)
			for _, rr := range m.Ns {
				rr.Header().Ttl = retry_time
				s.cache.Add(rr)
			}
			// Exponential backoff
			retry_time <<= 1
		}
		return false
	} else if r.Rcode != dns.RcodeSuccess {
		log.Printf("Server %s refused registration. Code: %s. Message: %s",
			s.Hostname, dns.RcodeToString[r.Rcode], getMessage(r))
		s.Stop()
		return false
	} else {
		if s.closing {
			log.Printf("Successfully removed %d addresses for name %s",
				len(r.Answer), s.Name)
			return true
		}

		log.Printf("Successfully registered %d addresses for name %s",
			len(r.Answer), s.Name)

		retry_time = 1

		// This set may be different from the records we sent for
		// registration since the server may be configured to drop some
		// records, and may restrict the allowed TTL.
		//
		// If the server drops the records, there is no use retrying
		// them again later, so keep and refresh the records that we
		// actually registered. And use the server-provided TTL for
		// deciding when to refresh.
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

	// We are shutting down; remove all entries
	if s.closing {
		m.Remove(rr)
		return s.send(m)
	}

	// When entries expire we check if the address still exists on one of
	// the configured interfaces, and use the current expiry time for the
	// new TTL
	addrs, err := getAddrs()
	if err != nil {
		return false
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
			if bytes.Compare(ip, a.IP.IP) == 0 {
				log.Printf("Refreshing record for IP %s", ip)
				r.Header().Ttl = getTTL(a.Ttl)
				m.Insert([]dns.RR{r})
			}
		}
	}

	return s.send(m)
}

func (s *Server) Stop() {
	close(s.nldone)
	s.finished <- true
}

func GenerateKey() {
	keyrr := &dns.KEY{dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(config.Name), Rrtype: dns.TypeKEY, Class: dns.ClassINET},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.ECDSAP384SHA384}}
	privkey, err := keyrr.Generate(384)
	if err != nil {
		log.Panic(err)
	}

	fi, err := os.Create(config.KeyFile)
	if err != nil {
		log.Panic(err)
	}
	fi.Write([]byte(keyrr.String()))
	fi.Close()

	pk := privkey.(*ecdsa.PrivateKey)

	fi, err = os.OpenFile(config.PrivateKeyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		log.Panic(err)
	}

	now := time.Now()
	time := fmt.Sprintf("%04d%02d%02d%02d%02d%02d",
		now.Year(),
		now.Month(),
		now.Day(),
		now.Hour(),
		now.Minute(),
		now.Second())
	fmt.Fprintf(fi, "Private-key-format: v1.3\n")
	fmt.Fprintf(fi, "Algorithm: %d (%s)\n",
		keyrr.Algorithm, dns.AlgorithmToString[keyrr.Algorithm])
	fmt.Fprintf(fi, "PrivateKey: %s\n", base64.StdEncoding.EncodeToString(pk.D.Bytes()))

	// These are not actually used, but dnssec-keygen writes them, so keep
	// them for compatibility
	fmt.Fprintf(fi, "Created: %s\n", time)
	fmt.Fprintf(fi, "Publish: %s\n", time)
	fmt.Fprintf(fi, "Activate: %s\n", time)
	fi.Close()

	log.Printf("Key generation successful.\n")
}

func readKeyFile() {
	if _, err := os.Stat(config.KeyFile); err != nil {
		if _, err := os.Stat(config.PrivateKeyFile); err != nil {
			if viper.GetBool("gen-key") {
				log.Printf("Generating new key file.")
				GenerateKey()
			}

		}
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

	switch rr.Header().Rrtype {
	case dns.TypeDNSKEY:
		// dnssec-keygen generates key records of type DNSKEY; convert
		// those to KEY
		keyrr = &dns.KEY{*rr.(*dns.DNSKEY)}
		keyrr.Hdr.Rrtype = dns.TypeKEY
	case dns.TypeKEY:
		keyrr = rr.(*dns.KEY)
	default:
		log.Panic("No KEY in keyfile")
	}
	fi, err = os.Open(config.PrivateKeyFile)
	if err != nil {
		log.Panic(err)
	}
	privkey, err = keyrr.ReadPrivateKey(fi, config.KeyFile)
	if err != nil {
		log.Panic(err)
	}
	keyrr.Hdr.Ttl = uint32(config.KeyTTL.Seconds())
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func readConfig() {
	var confdir string

	flag := pflag.FlagSet{}
	conffile := flag.StringP("conffile", "c", "", "Config file")

	flag.StringP("name", "n", "", "Name to register")
	viper.BindPFlag("name", flag.Lookup("name"))

	flag.StringSliceP("interface", "i", nil, "Interface to get addresses from")
	viper.BindPFlag("interfaces", flag.Lookup("interface"))

	flag.StringSliceP("address", "a", nil, "Extra address to register")
	viper.BindPFlag("extra-addresses", flag.Lookup("address"))

	flag.StringP("server", "s", "", "DNS server to use for lookup queries (add port separated with @)")
	viper.BindPFlag("dns-server", flag.Lookup("server"))

	flag.BoolP("tcp", "t", false, "Use TCP when communicating with server")
	viper.BindPFlag("dns-tcp", flag.Lookup("tcp"))

	flag.BoolP("keep", "k", false, "Do not remove records on shutdown")
	viper.BindPFlag("keep-records", flag.Lookup("keep"))

	flag.Bool("debug", false, "Print more debug information")
	viper.BindPFlag("debug", flag.Lookup("debug"))
	printf = flag.Bool("print", false, "Print replies (for debugging)")

	viper.SetDefault("debug", false)
	viper.SetDefault("discover-zones", true)
	viper.SetDefault("keep-records", false)
	viper.SetDefault("gen-key", true)
	viper.SetDefault("key-ttl", 720*time.Hour)
	viper.SetDefault("addr-ttl", 1*time.Hour)
	viper.SetDefault("dns-timeout", 10*time.Second)
	viper.SetDefault("key-file", "nsregc.key")
	viper.SetDefault("private-key-file", "nsregc.private")
	viper.SetDefault("interfaces", []string{})
	viper.SetDefault("zones", []string{})

	viper.SetDefault("exclude-subnets",
		[]string{"127.0.0.1/8",
			"::1/128",
			"fe80::/10",
			"169.254.0.0/16"})

	if hn, err := os.Hostname(); err == nil {
		viper.SetDefault("name", hn)
	}

	flag.Usage = func() {
		fmt.Printf("Usage: %s [options] [zone name] ... [zone name]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse(os.Args[1:])

	if len(*conffile) > 0 {
		ext := filepath.Ext(*conffile)
		if len(ext) == 0 || !stringInSlice(ext[1:], viper.SupportedExts) {
			log.Panic(fmt.Sprintf("Unknown configuration format: %s", *conffile))
		}
		viper.SetConfigType(ext[1:])

		fi, err := os.Open(*conffile)
		if err != nil {
			log.Panicf("Unable to open config file %s: %s \n",
				*conffile, err)
		}
		defer fi.Close()

		err = viper.ReadConfig(fi)
		if err != nil {
			log.Panicf("Fatal error reading config file: %s \n", err)
		}
		confdir = filepath.Dir(*conffile)
	} else {
		viper.SetConfigName("nsregc")
		viper.AddConfigPath("/etc/nsregc")
		viper.AddConfigPath("$HOME/.nsregc")
		err := viper.ReadInConfig()
		switch err.(type) {
		case viper.ConfigFileNotFoundError:
			log.Println("No config file found. Using defaults.")
			dir := filepath.Join(os.Getenv("HOME"), ".nsregc")
			confdir, err := filepath.Abs(dir)
			if err != nil {
				confdir = filepath.Clean(dir)
			}

			st, err := os.Stat(confdir)
			if err != nil {
				if err = os.Mkdir(confdir, 0700); err != nil {
					log.Panicf("Unable to create ~/.nsregc: %s \n", err)
				}
			} else if !st.IsDir() {
				log.Panic("~/.nsregc already exists but is not a directory")
			}
		case nil:
			log.Printf("Loaded config file %s", viper.ConfigFileUsed())
			confdir = filepath.Dir(viper.ConfigFileUsed())
		default:
			log.Panicf("Fatal error reading config file: %s \n", err)
		}
	}

	if len(viper.GetString("name")) == 0 {
		log.Panic("Must set name")
	}

	err := viper.Unmarshal(&config)
	if err != nil {
		log.Panicf("Fatal error parsing config file: %s \n", err)
	}

	if !filepath.IsAbs(config.KeyFile) {
		config.KeyFile = filepath.Join(confdir, config.KeyFile)
	}
	if !filepath.IsAbs(config.PrivateKeyFile) {
		config.PrivateKeyFile = filepath.Join(confdir, config.PrivateKeyFile)
	}

	for _, z := range flag.Args() {
		config.Zones = append(config.Zones, z)
	}

	config.excludedNets = make([]*net.IPNet, 0)
	for _, s := range viper.GetStringSlice("exclude-subnets") {
		_, net, err := net.ParseCIDR(s)
		if err != nil {
			log.Panic(err)
		}
		config.excludedNets = append(config.excludedNets, net)
	}

	config.extraAddrs = make([]*net.IPNet, 0)
	for _, a := range viper.GetStringSlice("extra-addresses") {
		ip := net.ParseIP(a)
		if ip == nil {
			log.Panicf("Unable to parse IP: %s", a)
		}
		config.extraAddrs = append(config.extraAddrs, &net.IPNet{IP: ip})
	}

	for i := range config.Zones {
		config.Zones[i] = dns.Fqdn(config.Zones[i])
	}
	//viper.Debug()
	//fmt.Printf("%s\n", config)
}

func getNameserver() string {
	var nameserver, port string

	parts := strings.SplitN(viper.GetString("dns-server"), "@", 2)
	nameserver = parts[0]

	if len(parts) > 1 && len(parts[1]) > 0 {
		if _, err := strconv.Atoi(parts[1]); err != nil {
			panic(fmt.Sprintf("Invalid DNS server: %s\n",
				viper.GetString("dns-server")))
		}
		port = parts[1]
	}

	if len(nameserver) == 0 {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		nameserver = conf.Servers[0]
	}

	if len(port) == 0 {
		port = "53"
	}

	// if the nameserver is from /etc/resolv.conf the [ and ] are already
	// added, thereby breaking net.ParseIP. Check for this and don't
	// fully qualify such a name
	if nameserver[0] == '[' && nameserver[len(nameserver)-1] == ']' {
		nameserver = nameserver[1 : len(nameserver)-1]
	}
	if i := net.ParseIP(nameserver); i != nil {
		nameserver = net.JoinHostPort(nameserver, port)
	} else {
		nameserver = dns.Fqdn(nameserver) + ":" + port
	}

	return nameserver
}

func discoverZones(nameserver string) {
	log.Println("Discovering zones to register with")

	// From RFC6763: Discover available zones by looking for PTR records in
	// .local as well as in each of the reverse zones for the network
	// address of each available IP address.
	//
	// We add .home.arpa to support homenets as defined in the IETF homenet
	// working group
	if addrs, err := getAddrs(); err == nil {
		for _, a := range addrs {
			if a.IP.Mask != nil {
				netaddr := a.IP.IP.Mask(a.IP.Mask)
				if d, err := dns.ReverseAddr(netaddr.String()); err == nil {
					discover_domains = append(discover_domains, d)
				}
			}
		}
	}
	c := new(dns.Client)
	if viper.GetBool("dns-tcp") {
		c.Net = "tcp"
	}
	c.Timeout = config.Timeout
	m := new(dns.Msg)
	m.SetEdns0(4096, true)

	for _, d := range discover_domains {
		m.SetQuestion(dns.Fqdn(discover_prefix+"."+d), dns.TypePTR)
		r, _, err := c.Exchange(m, nameserver)
		if err != nil {
			log.Printf("Error while discovering zones: %s", err)
			continue
		}

		if *printf {
			fmt.Println(r)
		}

		for _, k := range r.Answer {
			ptr, ok := k.(*dns.PTR)
			if ok && !stringInSlice(ptr.Ptr, config.Zones) {
				log.Printf("Found new registration zone '%s' from %s",
					ptr.Ptr, d)

				// We just append everything to config.Zones;
				// the code to lookup an nsregd server will
				// figure out which zones are actually supported
				config.Zones = append(config.Zones, ptr.Ptr)
			}
		}
	}

}

func main() {

	defer func() {
		if !viper.GetBool("debug") {
			recover() // suppress stack traces
		}
	}()

	readConfig()
	readKeyFile()

	nameserver := getNameserver()

	log.Printf("Using nameserver %s", nameserver)

	if viper.GetBool("discover-zones") {
		discoverZones(nameserver)
	}

	servers := 0
	exit := make(chan bool, len(config.Zones))
	for _, zone := range config.Zones {
		server, ok := getServer(dns.Fqdn(zone), nameserver, viper.GetBool("dns-tcp"))
		if !ok {
			log.Printf("No nsregd server found for zone %s", zone)
		} else {
			log.Printf("Found nsregd server %s for zone %s", server.Hostname, zone)
			servers += 1
			server.finished = exit
			defer func() {
				server.closing = true
				server.cache.Close(!viper.GetBool("keep-records"))
			}()
			go server.run()
		}
	}

	int := make(chan os.Signal)
	term := make(chan os.Signal)
	signal.Notify(int, syscall.SIGINT)
	signal.Notify(term, syscall.SIGTERM)

	for servers > 0 {
		select {
		case <-exit:
			servers -= 1
		case <-int:
			log.Println("Interrupted.")
			os.Exit(2)
		case <-term:
			log.Println("Received TERM, exiting.")
			os.Exit(0)
		}
	}

	log.Printf("All registration attempts failed with non-transient errors.")
	os.Exit(1)
}
