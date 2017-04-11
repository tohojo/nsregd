package main

import (
	"bytes"
	"sort"
	"time"

	"github.com/miekg/dns"
)

const (
	addRR cacheReqType = iota
	expireRRs
)

type cacheReqType int

type Cache struct {
	entries        map[string]CacheSlice /* entries mapped by name */
	expiryList     CacheSlice            /* entries sorted by expiry time */
	queue          chan CacheRequest
	expireCallback func(rr dns.RR) bool
}

type CacheSlice []*CacheEntry

type CacheEntry struct {
	rr     dns.RR
	expiry time.Time
}

type CacheRequest struct {
	reqType cacheReqType
	rr      dns.RR
	reply   chan bool
}

func (s CacheSlice) Len() int {
	return len(s)
}

func (s CacheSlice) Less(i, j int) bool {
	return s[i].expiry.Before(s[j].expiry)
}

func (s CacheSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s CacheSlice) Remove(e *CacheEntry) CacheSlice {
	idx := -1
	for i, o := range s {
		if o == e {
			idx = i
			break
		}
	}
	if idx > -1 {
		copy(s[idx:], s[idx+1:])
		s[len(s)-1] = nil
		return s[:len(s)-1]
	}
	return s
}

func (c *Cache) init() {
	c.entries = make(map[string]CacheSlice)
	c.expiryList = make(CacheSlice, 0, 10)
	c.queue = make(chan CacheRequest)

	go c.run()
}

func same(a, b dns.RR) bool {
	if a.Header().Rrtype != b.Header().Rrtype {
		return false
	}

	switch a.Header().Rrtype {
	case dns.TypeA:
		aa := a.(*dns.A)
		bb := b.(*dns.A)
		return bytes.Compare(aa.A, bb.A) == 0
	case dns.TypeAAAA:
		aa := a.(*dns.AAAA)
		bb := b.(*dns.AAAA)
		return bytes.Compare(aa.AAAA, bb.AAAA) == 0
	}
	return false
}

func after(seconds uint32) time.Time {
	return time.Now().Add(time.Duration(seconds) * time.Second)
}

func (c *Cache) run() {

	go func() {
		for {
			time.Sleep(expiryInterval)
			c.queue <- CacheRequest{reqType: expireRRs}
		}
	}()

	for req := range c.queue {
		switch req.reqType {
		case addRR:
			found := false
			name := req.rr.Header().Name
			if nc, ok := c.entries[name]; ok {
				for _, e := range nc {
					if same(e.rr, req.rr) {
						found = true
						e.expiry = after(req.rr.Header().Ttl)
						break
					}
				}
				if !found {
					ce := &CacheEntry{rr: req.rr,
						expiry: after(req.rr.Header().Ttl)}
					c.entries[name] = append(c.entries[name], ce)
					c.expiryList = append(c.expiryList, ce)
				}
			} else {
				nc = make(CacheSlice, 1, 5)
				nc[0] = &CacheEntry{rr: req.rr,
					expiry: after(req.rr.Header().Ttl)}
				c.expiryList = append(c.expiryList, nc[0])
			}
			sort.Sort(c.expiryList)
			req.reply <- found
		case expireRRs:
			for now := time.Now(); len(c.expiryList) > 0 && c.expiryList[0].expiry.Before(now); {
				e := c.expiryList[0]
				c.expiryList = c.expiryList[1:]

				name := e.rr.Header().Name
				c.expireCallback(e.rr)
				c.entries[name] = c.entries[name].Remove(e)
			}
		}
	}
}

/**
 * Add a RR to the cache. If it is not already in the cache,
 * add it and return true, otherwise refresh the expiry time
 * and return false.
 */
func (c *Cache) Add(rr dns.RR) bool {
	reply := make(chan bool)
	req := CacheRequest{reqType: addRR,
		rr:    rr,
		reply: reply,
	}
	c.queue <- req
	return <-reply
}
