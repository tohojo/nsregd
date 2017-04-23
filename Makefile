all: nsregd nsregc


nsregd: nsregd.go keydb.go cache.go util.go
	go build nsregd.go keydb.go cache.go util.go

nsregc: nsregc.go cache.go util.go
	go build nsregc.go cache.go util.go

.PHONY: clean
clean:
	rm -f nsregc nsregd

.PHONY: dep
dep:
	go get github.com/miekg/dns github.com/vishvananda/netlink github.com/spf13/pflag github.com/spf13/viper
