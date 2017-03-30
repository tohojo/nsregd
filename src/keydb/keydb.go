package keydb

import (
	"encoding/json"
	"fmt"
	"log"
	"io/ioutil"
	"os"
	"time"
)

const (
	addKey reqType = iota
	getKey
	refreshKey
	expireKeys

	timeout = 300 * time.Second
	expiryInterval = 5 * time.Second
)

type reqType int

type KeyDb struct {
	keys map[string]*Key
	queue chan keyRequest
	keyfile string
}

type Key struct {
	Name string `json:"name"`
	Secret string `json:"secret"`
	Expiry time.Time `json:"expiry"`
}

type keyRequest struct {
	reqType    reqType
	name       string
	secret     string
	resultChan chan string
}

func (db *KeyDb) run() {
	go func () {
		for {
			time.Sleep(expiryInterval)
			db.queue <- keyRequest{reqType: expireKeys}
		}
	}()

	for req := range db.queue {
		switch req.reqType {
		case addKey:
			if _, ok := db.keys[req.name]; !ok {
				db.keys[req.name] = &Key{
					Name: req.name,
					Secret: req.secret,
					Expiry: time.Now().Add(timeout),
				}
				req.resultChan <- "OK"
			} else {
				close(req.resultChan)
			}

		case getKey:
			if key, ok := db.keys[req.name]; ok {
				req.resultChan <- key.Secret
			} else {
				close(req.resultChan)
			}

		case refreshKey:
			if key,ok := db.keys[req.name]; ok {
				key.Expiry = time.Now().Add(timeout)
				req.resultChan <- "OK"
			} else {
				close(req.resultChan)
			}

		case expireKeys:
			for name, key := range db.keys {
				if key.Expiry.Before(time.Now()) {
					delete(db.keys, name)
				}
			}
		}
	}
}

func New(filename string) *KeyDb {
	db := KeyDb{
		keys: make(map[string]*Key),
		queue: make(chan keyRequest),
		keyfile: filename}

	defer func() {
		go db.run()
		db.queue <- keyRequest{reqType: expireKeys}
	}()

	if filename != "" {
		data, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Print(err)
			return &db
		}

		err = json.Unmarshal(data, &db.keys)
		if err != nil {
			log.Print(err)
			return &db
		}
	}

	return &db
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

func (db *KeyDb) Add(name, secret string) bool {
	req := keyRequest{
		reqType: addKey,
		name: name,
		secret: secret,
		resultChan: make(chan string)}
	db.queue <- req
	_, ok := <- req.resultChan
	return ok
}

func (db *KeyDb) Get(name string) (string, bool) {
	req := keyRequest{
		reqType: getKey,
		name: name,
		resultChan: make(chan string)}
	db.queue <- req
	secret, ok := <- req.resultChan
	return secret, ok
}

func (db *KeyDb) Refresh(name string) bool {
	req := keyRequest{
		reqType: refreshKey,
		name: name,
		resultChan: make(chan string)}
	db.queue <- req
	_, ok := <- req.resultChan
	return ok
}
