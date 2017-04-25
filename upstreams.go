package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"crypto/tls"
	"crypto/x509"
	"github.com/miekg/dns"
	"io/ioutil"
)

const (
	unbound_prefix = "UBCT1"
)

type Upstream interface {
	SendUpdate(records []dns.RR) bool
	Init(zone string) error
	Keep() bool
	String() string
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

func filterRRs(records []dns.RR, maxTtl time.Duration, filterIPs []*net.IPNet) []dns.RR {
	res := make([]dns.RR, 0)
	for _, orig := range records {
		rr := dns.Copy(orig)
		if rr.Header().Ttl > uint32(maxTtl.Seconds()) {
			rr.Header().Ttl = uint32(maxTtl.Seconds())
		}

		var ip net.IP
		switch rr.Header().Rrtype {
		case dns.TypeA:
			ip = rr.(*dns.A).A
		case dns.TypeAAAA:
			ip = rr.(*dns.AAAA).AAAA
		}

		if inNets(ip, filterIPs) {
			continue
		}
		res = append(res, rr)
	}
	return res
}

func genReverse(rr dns.RR) *dns.PTR {
	var ip net.IP
	switch rr.Header().Rrtype {
	case dns.TypeA:
		ip = rr.(*dns.A).A
	case dns.TypeAAAA:
		ip = rr.(*dns.AAAA).AAAA
	default:
		return nil
	}

	if rev, err := dns.ReverseAddr(ip.String()); err == nil {
		return &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   rev,
				Rrtype: dns.TypePTR,
				Ttl:    rr.Header().Ttl,
				Class:  rr.Header().Class},
			Ptr: rr.Header().Name}
	}

	return nil
}

func (nsup *NSUpstream) checkReverse(records []dns.RR) {
	for _, revzone := range nsup.ReverseZones {
		revzone = dns.Fqdn(revzone)

		upd := new(dns.Msg)
		upd.SetUpdate(revzone)

		for _, orig := range records {
			rr := genReverse(orig)

			if rr != nil && dns.IsSubDomain(revzone, rr.Header().Name) {
				upd.Ns = append(upd.Ns, rr)
			}
		}

		if len(upd.Ns) == 0 {
			continue
		}
		upd.SetTsig(nsup.TSigName, dns.HmacSHA256, 300, time.Now().Unix())

		hostname := nsup.Hostname + ":" + strconv.Itoa(int(nsup.Port))

		log.Printf("Sending nsupdate to %s with %d reverse names",
			hostname, len(upd.Ns))

		if *printf {
			fmt.Printf("Update message: %s", upd)
		}

		r, _, err := nsup.client.Exchange(upd, hostname)
		if err != nil {
			log.Printf("Error updating upstream DNS: %s", err)
		} else if r.Rcode != dns.RcodeSuccess {
			log.Printf("Upstream DNS update failed with error code %s",
				dns.RcodeToString[r.Rcode])
		} else {
			log.Printf("Upstream nsupdate of %s successful", hostname)
		}
	}
}

func (nsup *NSUpstream) SendUpdate(records []dns.RR) bool {
	upd := new(dns.Msg)
	upd.SetUpdate(nsup.Zone)
	upd.Ns = filterRRs(records, nsup.RecordTTL, nsup.excludeNets)
	upd.SetTsig(nsup.TSigName, dns.HmacSHA256, 300, time.Now().Unix())

	if len(upd.Ns) == 0 {
		log.Printf("No names to send to %s", nsup.Hostname)
		return true
	}

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
		nsup.checkReverse(upd.Ns)
	}

	return true
}

func (nsup *NSUpstream) Init(zone string) error {

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

func (nsup *NSUpstream) Keep() bool {
	return nsup.KeepRecords
}

func (nsup *NSUpstream) String() string {
	hostname := nsup.Hostname + ":" + strconv.Itoa(int(nsup.Port))
	return fmt.Sprintf("nsupdate (zone: %s hostname: %s)",
		nsup.Zone, hostname)
}

type UnboundUpstream struct {
	Hostname    string        `mapstructure:"hostname"`
	Port        uint16        `mapstructure:"port"`
	ClientCert  string        `mapstructure:"client-cert"`
	ClientKey   string        `mapstructure:"client-key"`
	ServerCert  string        `mapstructure:"server-cert"`
	ServerName  string        `mapstructure:"server-name"`
	Timeout     time.Duration `mapstructure:"timeout"`
	RecordTTL   time.Duration `mapstructure:"record-ttl"`
	KeepRecords bool          `mapstructure:"keep-records"`
	ExcludeNets []string      `mapstructure:"exclude-nets"`
	excludeNets []*net.IPNet
	tlsconfig   tls.Config
}

func (unbound *UnboundUpstream) Init(zone string) error {

	if err := checkFields(unbound); err != nil {
		return err
	}

	unbound.excludeNets = make([]*net.IPNet, 0, len(unbound.ExcludeNets))
	for _, n := range unbound.ExcludeNets {
		_, net, err := net.ParseCIDR(n)
		if err != nil {
			return err
		}
		unbound.excludeNets = append(unbound.excludeNets, net)
	}

	rootCA := x509.NewCertPool()

	data, err := ioutil.ReadFile(unbound.ServerCert)
	if err != nil {
		return err
	}
	ok := rootCA.AppendCertsFromPEM(data)
	if !ok {
		return fmt.Errorf("Unable to parse server certificate")
	}
	cert, err := tls.LoadX509KeyPair(unbound.ClientCert, unbound.ClientKey)
	if err != nil {
		return err
	}

	unbound.tlsconfig = tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   unbound.ServerName,
		RootCAs:      rootCA}
	unbound.tlsconfig.BuildNameToCertificate()

	return nil
}

func (unbound *UnboundUpstream) Keep() bool {
	return unbound.KeepRecords
}

func (unbound *UnboundUpstream) sendCmd(cmd string, extra []string) error {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("%s %s\n", unbound_prefix, cmd))

	for _, s := range extra {
		buf.WriteString(fmt.Sprintf("%s\n", s))
	}

	hostname := unbound.Hostname + ":" + strconv.Itoa(int(unbound.Port))

	if *printf {
		fmt.Printf("Unbound cmd: %s", buf.String())
	}

func (unbound *UnboundUpstream) String() string {
	hostname := unbound.Hostname + ":" + strconv.Itoa(int(unbound.Port))
	return fmt.Sprintf("unbound (%s)", hostname)
}

	dialer := net.Dialer{Timeout: unbound.Timeout}
	conn, err := tls.DialWithDialer(&dialer, "tcp", hostname, &unbound.tlsconfig)
	if err != nil {
		return err
	}
	defer conn.Close()

func (unbound *UnboundUpstream) String() string {
	hostname := unbound.Hostname + ":" + strconv.Itoa(int(unbound.Port))
	return fmt.Sprintf("unbound (%s)", hostname)
}

	conn.Write(buf.Bytes())

	rb := make([]byte, 0, 1024)
	_, err = conn.Read(rb)
	if err != nil {
		return err
	}
	if string(rb[:5]) == "error" {
		return fmt.Errorf("Unbound reported error: %s", rb)
	}
	return nil
}

func (unbound *UnboundUpstream) SendUpdate(records []dns.RR) bool {

	rrs := filterRRs(records, unbound.RecordTTL, unbound.excludeNets)
	if len(rrs) == 0 {
		log.Printf("No records to send to unbound")
		return true
	}

	// We need to remove all names and add them back, since Unbound has no
	// facility for removing a single record. Since there are both forward
	// and reverse addresses, we'll collect a list of names to remove which
	// includes the forward name and all the reverse names. These are always
	// removed, and all records that are not removals (i.e. with TTL>0) will
	// get added back afterwards.
	add_records := make([]string, 0, len(rrs)*2)
	remove_names := make([]string, 0, len(rrs)+1)
	for _, rr := range rrs {
		if !stringInSlice(rr.Header().Name, remove_names) {
			remove_names = append(remove_names, rr.Header().Name)
		}

		if rr.Header().Ttl > 0 {
			add_records = append(add_records, rr.String())
		}

		if rev := genReverse(rr); rev != nil {
			if rev.Header().Ttl > 0 {
				add_records = append(add_records, rev.String())
			}
			remove_names = append(remove_names, rev.Header().Name)
		}
	}

	err := unbound.sendCmd("local_datas_remove", remove_names)
	if err != nil {
		log.Printf("Error removing names from unbound: %s", err)
	}

	if len(add_records) == 0 {
		// All records were removals
		return true
	}

	log.Printf("Sending update to Unbound server at %s with %d names",
		unbound.Hostname, len(add_records))

	err = unbound.sendCmd("local_datas", add_records)
	if err != nil {
		log.Printf("Error communicating with unbound: %s", err)
		return false
	}

	return true
}
