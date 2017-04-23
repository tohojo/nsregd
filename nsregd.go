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
	"sync"
	"syscall"
	"time"

	"os/signal"
	"path/filepath"

	"github.com/miekg/dns"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	printf   *bool
	conffile *string
	Zones    map[string]*Zone
)

type Zone struct {
	Name          string        `mapstructure:"name"`
	MaxKeyTTL     time.Duration `mapstructure:"max-key-ttl"`
	MaxAddrTTL    time.Duration `mapstructure:"max-addr-ttl"`
	ReservedNames []string      `mapstructure:"reserved-names"`
	AllowAnyAddr  bool          `mapstructure:"allow-any-addr"`
	allowedNets   []*net.IPNet
	upstreams     []Upstream
	keydb         *KeyDb
	cache         *Cache
	lock          sync.RWMutex
}

type Upstream interface {
	sendUpdate(records []dns.RR) bool
	Init() error
}

type NSUpstream struct {
	Hostname     string        `mapstructure:"hostname"`
	Port         uint16        `mapstructure:"port"`
	TCP          bool          `mapstructure:"tcp"`
	Timeout      time.Duration `mapstructure:"timeout"`
	Zone         string        `mapstructure:"zone"`
	ReverseZones []string      `mapstructure:"reverse-zones"`
	RecordTTL    time.Duration `mapstructure:"record-ttl"`
	TSigName     string        `mapstructure:"tsig-name"`
	TSigSecret   string        `mapstructure:"tsig-secret"`
	KeepRecords  bool          `mapstructure:"keep-records"`
	ExcludeNets  []string      `mapstructure:"exclude-nets"`
	excludeNets  []*net.IPNet
	client       *dns.Client
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
		if rr.Header().Ttl > uint32(nsup.RecordTTL.Seconds()) {
			rr.Header().Ttl = uint32(nsup.RecordTTL.Seconds())
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

func (nsup *NSUpstream) Init() error {

	if err := checkFields(nsup); err != nil {
		return err
	}

	nsup.TSigName = dns.Fqdn(nsup.TSigName)
	nsup.Zone = dns.Fqdn(nsup.Zone)

	nsup.excludeNets = make([]*net.IPNet, 0, len(nsup.ExcludeNets))
	for _, n := range nsup.ExcludeNets {
		_, net, err := net.ParseCIDR(n)
		if err != nil {
			return err
		}
		nsup.excludeNets = append(nsup.excludeNets, net)
	}

	c := new(dns.Client)
	if nsup.TCP {
		c.Net = "tcp"
	}
	c.Timeout = nsup.Timeout
	c.TsigSecret = make(map[string]string)
	c.TsigSecret[nsup.TSigName] = nsup.TSigSecret

	nsup.client = c

	return nil
}

func (zone *Zone) Init() error {
	zone.lock.Lock()
	defer zone.lock.Unlock()

	zone.Name = dns.Fqdn(zone.Name)

	// zone.Name ends with .
	dbfile := zone.Name + "keydb"
	kdb, err := NewKeyDb(dbfile, uint32(zone.MaxKeyTTL.Seconds()), zone.removeName)
	if err != nil {
		return err
	}
	zone.keydb = kdb

	zone.cache = &Cache{ExpireCallback: zone.removeRRs,
		MaxTTL: uint32(zone.MaxAddrTTL.Seconds())}
	zone.cache.Init()

	dns.HandleFunc(zone.Name, zone.handleRegd)

	log.Printf("Configured zone %s", zone.Name)
	return nil
}

func (zone *Zone) UpdateConfig(other *Zone) error {
	zone.lock.Lock()
	defer zone.lock.Unlock()

	if zone.Name != other.Name {
		return fmt.Errorf("Cannot update zone %s from other zone with name %s",
			zone.Name, other.Name)
	}

	zone.keydb.Write()

	zone.MaxKeyTTL = other.MaxKeyTTL
	zone.MaxAddrTTL = other.MaxAddrTTL
	zone.ReservedNames = other.ReservedNames
	zone.AllowAnyAddr = other.AllowAnyAddr
	zone.allowedNets = other.allowedNets
	zone.upstreams = other.upstreams

	log.Printf("Updated config for zone %s", zone.Name)
	return nil
}

func (zone *Zone) Shutdown() {
	zone.lock.Lock()
	defer zone.lock.Unlock()

	zone.keydb.Stop()
	zone.cache.Close(true)
	dns.HandleRemove(zone.Name)
}

func (zone *Zone) validName(name string) bool {
	if !dns.IsSubDomain(zone.Name, name) {
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

	zone.lock.RLock()
	defer zone.lock.RUnlock()

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
			Port:   uint16(viper.GetInt("listen-port")),
			Target: dns.Fqdn(viper.GetString("listen-addr")),
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
			t := dns.Type(rrtype).String()
			if !zone.AllowAnyAddr && !zone.isIPAllowed(ip) {
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

func configureZone(zonename string, conf *viper.Viper) {
	var err error

	zonename = dns.Fqdn(zonename)

	zone := new(Zone)

	zone.Name = zonename
	zone.ReservedNames = make([]string, 0)
	zone.allowedNets = make([]*net.IPNet, 0)
	zone.upstreams = make([]Upstream, 0)

	if err = conf.Unmarshal(zone); err == nil {
		err = checkFields(zone)
	}
	if err != nil {
		log.Printf("Unable to parse zone config for zone %s: %s",
			zonename, err)
		return
	}

	for _, n := range conf.GetStringSlice("allowed-nets") {
		_, net, err := net.ParseCIDR(n)
		if err != nil {
			log.Printf("Zone %s: Invalid CIDR in allowed-nets: %s",
				zonename, n)
			return
		}
		zone.allowedNets = append(zone.allowedNets, net)
	}

	upstreams := make([]map[string]interface{}, 0)
	if err := conf.UnmarshalKey("upstreams", &upstreams); err != nil {
		log.Printf("Zone %s: Unable to parse upstreams: %s", zonename, err)
		return
	}

	for _, u := range upstreams {
		var ups Upstream
		switch u["type"] {
		case "nsupdate":
			ups = new(NSUpstream)
		case nil:
			log.Printf("Zone %s: Missing upstream type", zonename)
			return
		default:
			log.Printf("Zone %s: Unknown upstream type '%s'", zonename, u["type"])
			return
		}

		dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			Metadata:         nil,
			Result:           ups,
			WeaklyTypedInput: true,
			ZeroFields:       true,
			DecodeHook:       mapstructure.StringToTimeDurationHookFunc(),
		})
		if err = dec.Decode(u); err == nil {
			err = ups.Init()
		}
		if err != nil {
			log.Printf("Zone %s: Error parsing upstream type: %s",
				zonename, err)
			return
		}
		zone.upstreams = append(zone.upstreams, ups)
	}

	if z, ok := Zones[zonename]; ok {
		z.UpdateConfig(zone)
	} else {
		if err := zone.Init(); err == nil {
			Zones[zonename] = zone
		}
	}
}

func initConfig() {
	Zones = make(map[string]*Zone)

	flag := pflag.FlagSet{}
	conffile = flag.StringP("conffile", "c", "", "Config file")

	flag.Bool("debug", false, "Print more debug information")
	viper.BindPFlag("debug", flag.Lookup("debug"))

	printf = flag.Bool("print", false, "Print replies (for debugging)")

	viper.SetDefault("debug", false)
	viper.SetDefault("listen-addr", "localhost")
	viper.SetDefault("listen-port", 8053)
	viper.SetDefault("data-dir", "/var/lib/nsregd")

	flag.Parse(os.Args[1:])

}

func readConfig() {
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
	} else {
		viper.SetConfigName("nsregd")
		viper.AddConfigPath("/etc/nsregd")
		err := viper.ReadInConfig()
		if err != nil {
			log.Panicf("Fatal error reading config file: %s \n", err)
		}
		log.Printf("Loaded config file %s", viper.ConfigFileUsed())
	}

	zonemap := viper.GetStringMap("zones")
	confzones := make([]string, 0, len(zonemap))
	for zone, _ := range zonemap {
		configureZone(zone, viper.Sub("zones."+zone))
		confzones = append(confzones, dns.Fqdn(zone))
	}
	for n, z := range Zones {
		if !stringInSlice(n, confzones) {
			z.Shutdown()
			delete(Zones, n)
		}
	}
}

func main() {

	initConfig()
	readConfig()

	laddr := viper.GetString("listen-addr") + ":" + strconv.Itoa(viper.GetInt("listen-port"))
	server4 := &dns.Server{Addr: laddr, Net: "tcp4"}
	log.Printf("Starting server on %s (tcp4)", laddr)
	go serve(server4)

	server6 := &dns.Server{Addr: laddr, Net: "tcp6"}
	log.Printf("Starting server on %s (tcp6)", laddr)
	go serve(server6)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	defer func() {
		server4.Shutdown()
		server6.Shutdown()

		for _, z := range Zones {
			z.Shutdown()
		}

		if !viper.GetBool("debug") {
			recover() // suppress stack traces
		}
	}()

	log.Printf("Started. Serving %d zones.", len(Zones))

	for {
		switch <-sig {
		case syscall.SIGINT:
			log.Println("Interrupted")
			os.Exit(2)
		case syscall.SIGTERM:
			log.Println("Received TERM, shutting down")
			os.Exit(0)
		case syscall.SIGHUP:
			log.Println("Received HUP, re-reading config")
			readConfig()
		}
	}

}
