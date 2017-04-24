package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

type Upstream interface {
	SendUpdate(records []dns.RR) bool
	Init() error
	Keep() bool
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

func (nsup *NSUpstream) checkReverse(records []dns.RR) {
	for _, revzone := range nsup.ReverseZones {
		revzone = dns.Fqdn(revzone)

		upd := new(dns.Msg)
		upd.SetUpdate(revzone)

		for _, orig := range records {
			rr := dns.Copy(orig)

			var ip net.IP
			switch rr.Header().Rrtype {
			case dns.TypeA:
				ip = rr.(*dns.A).A
			case dns.TypeAAAA:
				ip = rr.(*dns.AAAA).AAAA
			}

			rev, err := dns.ReverseAddr(ip.String())
			if err == nil && dns.IsSubDomain(revzone, rev) {
				newrr := &dns.PTR{
					Hdr: dns.RR_Header{
						Name:   rev,
						Rrtype: dns.TypePTR,
						Ttl:    rr.Header().Ttl,
						Class:  rr.Header().Class},
					Ptr: rr.Header().Name}
				upd.Ns = append(upd.Ns, newrr)
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

	for _, orig := range records {
		rr := dns.Copy(orig)
		if rr.Header().Ttl > uint32(nsup.RecordTTL.Seconds()) {
			rr.Header().Ttl = uint32(nsup.RecordTTL.Seconds())
		}

		var ip net.IP
		switch rr.Header().Rrtype {
		case dns.TypeA:
			ip = rr.(*dns.A).A
		case dns.TypeAAAA:
			ip = rr.(*dns.AAAA).AAAA
		}

		if inNets(ip, nsup.excludeNets) {
			continue
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
		nsup.checkReverse(upd.Ns)
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

func (nsup *NSUpstream) Keep() bool {
	return nsup.KeepRecords
}
