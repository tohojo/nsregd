package main

import (
	"bytes"
	"sort"
	"time"

	"github.com/miekg/dns"
)

const (
	addRR cacheReqType = iota
	checkRR
	removeRR
	removeName
	expireRRs
)

type cacheReqType int

type Cache struct {
	entries        map[string]CacheSlice /* entries mapped by name */
	expiryList     CacheSlice            /* entries sorted by expiry time */
	queue          chan CacheRequest
	ExpireCallback func(rr []dns.RR) bool
	MaxTTL         uint32
}

type CacheSlice []*CacheEntry

type CacheEntry struct {
	rr     dns.RR
	expiry time.Time
}

type CacheRequest struct {
	reqType cacheReqType
	rr      dns.RR
	name    string
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

func (c *Cache) Init() {
	c.entries = make(map[string]CacheSlice)
	c.expiryList = make(CacheSlice, 0, 10)
	c.queue = make(chan CacheRequest)

	go c.run()
}

/* return true if we added a new entry */
func (c *Cache) addRR(rr dns.RR) bool {
	name := rr.Header().Name
	ttl := c.clampTTL(rr)
	if ttl == 0 {
		return false
	}
	if nc, ok := c.entries[name]; ok {
		for _, e := range nc {
			if same(e.rr, rr) {
				e.rr.Header().Ttl = ttl
				e.expiry = after(ttl)
				sort.Sort(c.expiryList)
				return false
			}
		}
		/* cache entry exists for name, but not for this RR */
		ce := &CacheEntry{rr: rr,
			expiry: after(ttl)}
		c.entries[name] = append(c.entries[name], ce)
		c.expiryList = append(c.expiryList, ce)
		sort.Sort(c.expiryList)
		return true
	} else {
		/* no prior cache entires for this name */
		nc = make(CacheSlice, 1, 5)
		nc[0] = &CacheEntry{rr: rr,
			expiry: after(ttl)}
		c.entries[name] = nc
		c.expiryList = append(c.expiryList, nc[0])
		sort.Sort(c.expiryList)
		return true
	}
}

func (c *Cache) checkRR(rr dns.RR) bool {
	name := rr.Header().Name
	if nc, ok := c.entries[name]; ok {
		for _, e := range nc {
			if same(e.rr, rr) {
				return true
			}
		}
	}
	return false
}

func (c *Cache) removeRR(rr dns.RR) bool {
	name := rr.Header().Name
	if nc, ok := c.entries[name]; ok {
		for _, e := range nc {
			if same(e.rr, rr) {
				c.entries[name] = nc.Remove(e)
				c.expiryList = c.expiryList.Remove(e)
				return true
			}
		}
	}
	return false
}

func (c *Cache) removeName(name string) bool {
	if nc, ok := c.entries[name]; ok {
		for _, e := range nc {
			c.expiryList = c.expiryList.Remove(e)
		}
		delete(c.entries, name)
		return true
	}
	return false
}

func (c *Cache) run() {

	done := make(chan bool)

	go func() {
		for {
			time.Sleep(time.Second)
			select {
			case <-done:
				return
			default:
				c.queue <- CacheRequest{reqType: expireRRs}
			}
		}
	}()

	for req := range c.queue {
		switch req.reqType {
		case addRR:
			req.reply <- c.addRR(req.rr)
		case checkRR:
			req.reply <- c.checkRR(req.rr)
		case removeRR:
			req.reply <- c.removeRR(req.rr)
		case removeName:
			req.reply <- c.removeName(req.name)
		case expireRRs:
			rr := make([]dns.RR, 0)
			for now := time.Now(); len(c.expiryList) > 0 && c.expiryList[0].expiry.Before(now); {
				e := c.expiryList[0]
				c.expiryList = c.expiryList[1:]

				name := e.rr.Header().Name
				c.entries[name] = c.entries[name].Remove(e)
				rr = append(rr, e.rr)
			}
			if len(rr) > 0 {
				go c.ExpireCallback(rr)
			}
		}
	}
	done <- true
}

func (c *Cache) clampTTL(rr dns.RR) uint32 {
	if rr.Header().Ttl > c.MaxTTL {
		rr.Header().Ttl = c.MaxTTL
	}
	return rr.Header().Ttl
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

func (c *Cache) Check(rr dns.RR) bool {
	reply := make(chan bool)
	req := CacheRequest{reqType: checkRR,
		rr:    rr,
		reply: reply,
	}
	c.queue <- req
	return <-reply
}

func (c *Cache) Remove(rr dns.RR) bool {
	reply := make(chan bool)
	req := CacheRequest{reqType: removeRR,
		rr:    rr,
		reply: reply,
	}
	c.queue <- req
	return <-reply
}

func (c *Cache) RemoveName(name string) bool {
	reply := make(chan bool)
	req := CacheRequest{reqType: removeName,
		name:  name,
		reply: reply,
	}
	c.queue <- req
	return <-reply
}

func (c *Cache) Close(runCallback bool) {
	close(c.queue)
	if runCallback && len(c.expiryList) > 0 {
		rr := make([]dns.RR, len(c.expiryList))
		for i, e := range c.expiryList {
			rr[i] = e.rr
		}
		c.ExpireCallback(rr)
	}
}
