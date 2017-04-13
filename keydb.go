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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"
)

const (
	addKey keyReqType = iota
	getKey
	refreshKey
	expireKeys
)

type keyReqType int

type KeyDb struct {
	keys           map[string]*Key
	queue          chan keyRequest
	timeout        time.Duration
	keyfile        string
	expireCallback func(name string) bool
}

type Key struct {
	Name      string
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	KeyTag    uint16
	PublicKey string
	Expiry    time.Time
}

type keyRequest struct {
	reqType    keyReqType
	name       string
	key        *Key
	resultChan chan *Key
}

func (db *KeyDb) run() {
	done := make(chan bool)
	go func() {
		for {
			time.Sleep(time.Second)
			select {
			case <-done:
				return
			default:
				db.queue <- keyRequest{reqType: expireKeys}
			}
		}
	}()

	for req := range db.queue {
		switch req.reqType {
		case addKey:
			if _, ok := db.keys[req.key.Name]; !ok {
				req.key.Expiry = time.Now().Add(db.timeout)
				db.keys[req.key.Name] = req.key
				req.resultChan <- nil
			} else {
				close(req.resultChan)
			}

		case getKey:
			if key, ok := db.keys[req.name]; ok {
				req.resultChan <- key
			} else {
				close(req.resultChan)
			}

		case refreshKey:
			if key, ok := db.keys[req.name]; ok {
				key.Expiry = time.Now().Add(db.timeout)
				req.resultChan <- nil
			} else {
				close(req.resultChan)
			}

		case expireKeys:
			for name, key := range db.keys {
				if key.Expiry.Before(time.Now()) {
					delete(db.keys, name)
					go db.expireCallback(name)
				}
			}
		}
	}
	done <- true
}

func NewKeyDb(filename string, keytimeout uint, callback func(name string) bool) (*KeyDb, error) {
	db := KeyDb{
		keys:           make(map[string]*Key),
		queue:          make(chan keyRequest),
		timeout:        time.Duration(keytimeout) * time.Second,
		keyfile:        filename,
		expireCallback: callback}

	defer func() {
		go db.run()
		db.queue <- keyRequest{reqType: expireKeys}
	}()

	if filename != "" {
		data, err := ioutil.ReadFile(filename)
		if os.IsNotExist(err) {
			return &db, nil
		} else if err != nil {
			log.Print(err)
			return &db, err
		}

		err = json.Unmarshal(data, &db.keys)
		if err != nil {
			log.Print(err)
			return &db, err
		}
	}

	return &db, nil
}

func (db *KeyDb) Stop() {
	close(db.queue)

	if db.keyfile != "" {
		data, err := json.Marshal(db.keys)
		if err != nil {
			log.Fatal(err)
		}

		fn := fmt.Sprintf("%s.tmp", db.keyfile)
		fp, err := os.Create(fn)
		if err != nil {
			log.Fatal(err)
		}

		_, err = fp.Write(data)
		fp.Close()

		if err == nil {
			err = os.Rename(fn, db.keyfile)
		}

		if err != nil {
			log.Fatal(err)
		}
	}
}

func (db *KeyDb) Add(key *Key) bool {
	req := keyRequest{
		reqType:    addKey,
		key:        key,
		resultChan: make(chan *Key)}
	db.queue <- req
	_, ok := <-req.resultChan
	return ok
}

func (db *KeyDb) Get(name string) (*Key, bool) {
	req := keyRequest{
		reqType:    getKey,
		name:       name,
		resultChan: make(chan *Key)}
	db.queue <- req
	key, ok := <-req.resultChan
	return key, ok
}

func (db *KeyDb) Refresh(name string) bool {
	req := keyRequest{
		reqType:    refreshKey,
		name:       name,
		resultChan: make(chan *Key)}
	db.queue <- req
	_, ok := <-req.resultChan
	return ok
}
