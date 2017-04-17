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
	flag "github.com/spf13/pflag"
)

var (
	printf   = flag.Bool("print", false, "print replies")
	keep     = flag.BoolP("keep", "k", false, "do not flush entries from upstreams on shutdown")
	conffile = flag.String("conffile", "", "Config file")
	config   Config
)

type Config struct {
	ListenAddr string
	ListenPort int
	Zones      []*Zone
}

type Zone struct {
	Name          string
	Upstreams     UpstreamList
	upstreams     []Upstream
	ReservedNames []string
	AllowedNets   []string
	AllowAnyNet   bool
	allowedNets   []*net.IPNet
	KeyDbFile     string
	MaxKeyTTL     uint32
	MaxTTL        uint32
	keydb         *KeyDb
	cache         *Cache
}

type UpstreamList struct {
	NSUpdate []NSUpstream
}

type Upstream interface {
	sendUpdate(records []dns.RR) bool
	Init()
}

type NSUpstream struct {
	Type       string
	Hostname   string
	Port       uint16
	Zone       string
	TSigName   string
	TSigSecret string
	MaxTTL     uint32
	TCP        bool
	Timeout    string
	client     *dns.Client
}

func setError(m *dns.Msg, name string, code int, msg string) {
	m.Rcode = code
	if m.Extra == nil {
		m.Extra = make([]dns.RR, 0, 1)
	}
	m.Extra = append(m.Extra, &dns.TXT{
		Hdr: dns.RR_Header{Name: name,
			Rrtype: dns.TypeTXT,
			Ttl:    0,
			Class:  dns.ClassANY},
		Txt: []string{msg}})
}

func (nsup *NSUpstream) sendUpdate(records []dns.RR) bool {
	upd := new(dns.Msg)
	upd.SetUpdate(nsup.Zone)

	for _, orig := range records {
		rr := dns.Copy(orig)
		if rr.Header().Ttl > nsup.MaxTTL {
			rr.Header().Ttl = nsup.MaxTTL
		}
		upd.Ns = append(upd.Ns, rr)
	}

	upd.SetTsig(nsup.TSigName, dns.HmacSHA256, 300, time.Now().Unix())

	hostname := nsup.Hostname + ":" + strconv.Itoa(int(nsup.Port))

	log.Printf("Sending nsupdate to %s with %d names", hostname, len(upd.Ns))

	if *printf {
		fmt.Printf("Update message: %s", upd)
	}

	r, _, err := nsup.client.Exchange(upd, hostname)

	if err != nil {
		log.Printf("Error updating upstream DNS: %s", err)
		return false
	} else if r.Rcode != dns.RcodeSuccess {
		log.Printf("Upstream DNS update failed with error code %s",
			dns.RcodeToString[r.Rcode])
		return false
	} else {
		log.Printf("Upstream nsupdate of %s successful", hostname)
	}

	return true
}

func (nsup *NSUpstream) Init() {
	nsup.TSigName = dns.Fqdn(nsup.TSigName)
	nsup.Zone = dns.Fqdn(nsup.Zone)

	c := new(dns.Client)
	if nsup.TCP {
		c.Net = "tcp"
	}
	c.Timeout, _ = time.ParseDuration(nsup.Timeout)
	c.TsigSecret = make(map[string]string)
	c.TsigSecret[nsup.TSigName] = nsup.TSigSecret

	nsup.client = c
}

func (zone *Zone) validName(name string) bool {
	if dns.CompareDomainName(name, zone.Name) != dns.CountLabel(zone.Name) {
		return false
	}
	if dns.CountLabel(name)-dns.CountLabel(zone.Name) != 1 {
		return false
	}

	for _, n := range zone.ReservedNames {
		if n+"."+zone.Name == name {
			return false
		}
	}

	return true
}

func (zone *Zone) verifySig(m *dns.Msg, remoteIP net.IP, reply *dns.Msg) (name string, success bool) {

	var (
		sigrr *dns.SIG
		keyrr *dns.KEY
	)

	for _, rr := range m.Extra {
		if k, ok := rr.(*dns.KEY); ok {
			if keyrr != nil {
				setError(reply, rr.Header().Name, dns.RcodeFormatError,
					"Duplicate KEY RR")
				return
			}
			keyrr = k
		}
		if s, ok := rr.(*dns.SIG); ok {
			if sigrr != nil {
				setError(reply, rr.Header().Name, dns.RcodeFormatError,
					"Duplicate SIG RR")
				return
			}
			sigrr = s
		}
	}

	if sigrr == nil {
		setError(reply, zone.Name, dns.RcodeFormatError,
			"No SIG RR found")
		return
	}
	if keyrr == nil {
		log.Printf("Got query for %s without KEY from %s.", name, remoteIP)
		setError(reply, zone.Name, dns.RcodeFormatError,
			"No KEY RR found")
		return
	}
	if keyrr.Header().Ttl == 0 {
		log.Printf("Got query for %s with 0-TTL KEY from %s.", name, remoteIP)
		setError(reply, zone.Name, dns.RcodeFormatError,
			"KEY RR must have TTL>0")
		return
	}

	name = sigrr.SignerName

	buf, err := m.Pack()
	if err != nil {
		setError(reply, zone.Name, dns.RcodeFormatError,
			"Error verifying signature")
		return
	}

	key, ok := zone.keydb.Get(name)
	if ok {
		/* Found existing key, verify sig */
		if key.KeyTag != sigrr.KeyTag {
			log.Printf("Got sig for %s with wrong keytag from %s.", name, remoteIP)
			setError(reply, name, dns.RcodeRefused,
				"Invalid key for name")
			return
		}
		if keyrr.Hdr.Name != name ||
			keyrr.Flags != key.Flags ||
			keyrr.Protocol != key.Protocol ||
			keyrr.Algorithm != key.Algorithm ||
			keyrr.PublicKey != key.PublicKey {

			log.Printf("Got wrong KEY for %s from %s.", name, remoteIP)
			setError(reply, name, dns.RcodeRefused,
				"Invalid KEY for name")
			return
		}

		err := sigrr.Verify(keyrr, buf)
		if err == nil {
			log.Printf("Verified sig with existing key for %s from %s.",
				name, remoteIP)
			zone.keydb.Refresh(name, keyrr.Header().Ttl)
			return name, true
		} else {
			log.Printf("Failed to verify sig for %s from %s.", name, remoteIP)
			setError(reply, name, dns.RcodeNotAuth,
				"Signature verifyication failed")
		}
	} else {
		/* No existing key, keep if in valid dom */
		if !zone.isIPAllowed(remoteIP) {
			log.Printf("Disallowed attempt from  %s to add new key.", remoteIP)
			setError(reply, name, dns.RcodeRefused,
				"Remote addr not allowed to add new key")
			return
		}
		if !zone.validName(name) {
			log.Printf("Got disallowed new name %s from %s.", name, remoteIP)
			setError(reply, name, dns.RcodeRefused,
				"Name disallowed by server config")
			return
		}

		err := sigrr.Verify(keyrr, buf)
		if err == nil {
			log.Printf("Verified sig with new key for %s from %s.", name, remoteIP)
			key = &Key{
				Name:      name,
				Flags:     keyrr.Flags,
				Protocol:  keyrr.Protocol,
				Algorithm: keyrr.Algorithm,
				KeyTag:    keyrr.KeyTag(),
				PublicKey: keyrr.PublicKey}
			if zone.keydb.Add(key, keyrr.Header().Ttl) {
				return name, true
			}
		}
	}
	setError(reply, zone.Name, dns.RcodeNotAuth,
		"Signature verification failed")

	return name, false
}

func (zone *Zone) isIPAllowed(ip net.IP) bool {

	for _, net := range zone.allowedNets {
		if net.Contains(ip) {
			return true
		}
	}

	return false
}

func (zone *Zone) sendUpdates(records []dns.RR) bool {
	success := true

	if len(zone.upstreams) == 0 {
		log.Printf("No upstreams configured for zone %s", zone.Name)
		return false
	}
	for _, u := range zone.upstreams {
		success = success && u.sendUpdate(records)
	}
	return success
}

func (zone *Zone) removeName(name string) bool {
	success := true

	log.Printf("Removing name: %s", name)

	records := make([]dns.RR, 1)
	records[0] = &dns.ANY{Hdr: dns.RR_Header{Name: name, Ttl: 0, Rrtype: dns.TypeANY, Class: dns.ClassANY}}

	for _, u := range zone.upstreams {
		success = success && u.sendUpdate(records)
	}

	zone.cache.removeName(name)

	return success
}

func (zone *Zone) removeRRs(rr []dns.RR) bool {
	success := true

	records := make([]dns.RR, 0, len(rr))

	for _, r := range rr {
		log.Printf("Removing RR: %s", r)
		r.Header().Class = dns.ClassNONE
		r.Header().Ttl = 0
		records = append(records, r)
	}

	for _, u := range zone.upstreams {
		success = success && u.sendUpdate(records)
	}

	return success
}

func getIP(rr dns.RR) net.IP {
	if a, ok := rr.(*dns.A); ok {
		return a.A
	}
	if aaaa, ok := rr.(*dns.AAAA); ok {
		return aaaa.AAAA
	}
	return nil
}

func (zone *Zone) handleRegd(w dns.ResponseWriter, r *dns.Msg) {

	var (
		name    string
		ok      bool
		records []dns.RR
	)

	var remoteIP net.IP
	switch v := w.RemoteAddr().(type) {
	case *net.TCPAddr:
		remoteIP = v.IP
	case *net.UDPAddr:
		remoteIP = v.IP
	}

	if *printf {
		fmt.Printf("%s: Received msg from %s: %s", zone.Name, remoteIP, r)
	}

	m := new(dns.Msg)
	m.SetReply(r)

	if r.MsgHdr.Opcode == dns.OpcodeQuery && r.Question[0].Qtype == dns.TypeSRV {
		q := r.Question[0]
		rr := &dns.SRV{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSRV,
				Class: dns.ClassINET, Ttl: 0},
			Port:   uint16(config.ListenPort),
			Target: dns.Fqdn(config.ListenAddr),
		}
		m.Answer = append(m.Answer, rr)
		goto out
	}

	if r.MsgHdr.Opcode != dns.OpcodeUpdate {
		log.Printf("Got non-update query from %s.", remoteIP)
		setError(m, zone.Name, dns.RcodeRefused, "Non-update query refused")
		goto out
	}

	name, ok = zone.verifySig(r, remoteIP, m)
	if !ok {
		goto out
	}

	records = make([]dns.RR, 0, len(r.Ns))

	for _, rr := range r.Ns {
		if rr.Header().Name != name {
			log.Printf("Got malformed query from %s (record for wrong name %s).",
				remoteIP, rr.Header().Name)
			setError(m, rr.Header().Name, dns.RcodeRefused,
				"Found record with non-authorized name")
			goto out
		}
		rrtype := rr.Header().Rrtype
		switch rrtype {
		case dns.TypeA, dns.TypeAAAA:
			ip := getIP(rr)
			t := dns.TypeToString[rrtype]
			if !zone.AllowAnyNet && !zone.isIPAllowed(ip) {
				log.Printf("Skipping %s record for %s outside allowed ranges from %s.",
					t, ip, remoteIP)
				continue
			}
			if rr.Header().Ttl == 0 {
				if rr.Header().Class != dns.ClassNONE {
					setError(m, name,
						dns.RcodeFormatError,
						"TTL 0 record with class != NONE")
					goto out
				}
				log.Printf("Got removal for %s record for address %s from %s.",
					t, ip, remoteIP)
				zone.cache.Remove(rr)
				records = append(records, rr)
			} else if zone.cache.Add(rr) {
				log.Printf("Got new %s record for address %s with TTL %d from %s.",
					t, ip, rr.Header().Ttl, remoteIP)
				records = append(records, rr)
			} else {
				log.Printf("Refreshed %s record for address %s with TTL %d from %s.",
					t, ip, rr.Header().Ttl, remoteIP)
			}
			m.Answer = append(m.Answer, rr)
		default:
			log.Printf("Got query with invalid record type %d from %s.",
				rrtype, remoteIP)
			setError(m, name, dns.RcodeRefused, "Invalid record type in query")
			goto out
		}

	}

	if len(records) == 0 {
		log.Print("No new (non-cached) records, not sending update.")
	} else if !zone.sendUpdates(records) {
		setError(m, name,
			dns.RcodeServerFailure, "Unable to update upstream servers")
	}

out:
	if *printf {
		log.Printf("Sending reply to %s: %v", remoteIP, m.String())
	}

	err := w.WriteMsg(m)
	if err != nil {
		log.Printf("error on write: %s", err.Error())
	}
}

func serve(server *dns.Server) {
	if err := server.ListenAndServe(); err != nil {
		switch e := err.(type) {
		case *net.OpError:
			if e.Op == "accept" && e.Err.Error() == "use of closed network connection" {
				// We get this when shutting down, so don't complain about it
				return
			}
		}
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

	for _, zone := range config.Zones {
		zone.Name = dns.Fqdn(zone.Name)

		zone.upstreams = make([]Upstream, 0)
		for _, upstream := range zone.Upstreams.NSUpdate {
			upstream.Init()
			zone.upstreams = append(zone.upstreams, &upstream)
		}

		kdb, err := NewKeyDb(zone.KeyDbFile, zone.MaxKeyTTL, zone.removeName)
		if err != nil {
			return
		}
		log.Printf("Configuring zone %s with db file %s", zone.Name, zone.KeyDbFile)
		zone.keydb = kdb
		defer kdb.Stop()

		zone.cache = &Cache{ExpireCallback: zone.removeRRs,
			MaxTTL: zone.MaxTTL}
		zone.cache.Init()
		defer zone.cache.Close(!*keep)

		for _, n := range zone.AllowedNets {
			_, net, err := net.ParseCIDR(n)
			if err != nil {
				log.Panic(err)
			}
			zone.allowedNets = append(zone.allowedNets, net)
		}

		dns.HandleFunc(zone.Name, zone.handleRegd)
	}

	laddr := config.ListenAddr + ":" + strconv.Itoa(config.ListenPort)
	server4 := &dns.Server{Addr: laddr, Net: "tcp4"}
	log.Printf("Starting server on %s (tcp4)", laddr)
	go serve(server4)

	server6 := &dns.Server{Addr: laddr, Net: "tcp6"}
	log.Printf("Starting server on %s (tcp6)", laddr)
	go serve(server6)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)

	server4.Shutdown()
	server6.Shutdown()
}
