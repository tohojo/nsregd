package nsregd

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
	keys map[string]Key
	queue chan keyRequest
	keyfile string
}

type Key struct {
	Name string `json:"name"`
	Flags uint16 `json:"flags"`
	Protocol uint8 `json:"protocol"`
	Algorithm uint8 `json:"algorithm"`
	PublicKey string `json:"pubkey"`
	Expiry time.Time `json:"expiry"`
}

type keyRequest struct {
	reqType    reqType
	name       string
	key        Key
	resultChan chan Key
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
			if _, ok := db.keys[req.key.Name]; !ok {
				req.key.Expiry = time.Now().Add(timeout)
				db.keys[req.key.Name] = req.key
				req.resultChan <- Key{}
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
			if key,ok := db.keys[req.name]; ok {
				key.Expiry = time.Now().Add(timeout)
				req.resultChan <- Key{}
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

func NewKeyDb(filename string) *KeyDb {
	db := KeyDb{
		keys: make(map[string]Key),
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

func (db *KeyDb) Add(key Key) bool {
	req := keyRequest{
		reqType: addKey,
		key: key,
		resultChan: make(chan Key)}
	db.queue <- req
	_, ok := <- req.resultChan
	return ok
}

func (db *KeyDb) Get(name string) (Key, bool) {
	req := keyRequest{
		reqType: getKey,
		name: name,
		resultChan: make(chan Key)}
	db.queue <- req
	key, ok := <- req.resultChan
	return key, ok
}

func (db *KeyDb) Refresh(name string) bool {
	req := keyRequest{
		reqType: refreshKey,
		name: name,
		resultChan: make(chan Key)}
	db.queue <- req
	_, ok := <- req.resultChan
	return ok
}
