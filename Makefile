all: nsregd nsregc


nsregd: nsregd.go keydb.go cache.go
	go build nsregd.go keydb.go cache.go

nsregc: nsregc.go cache.go
	go build nsregc.go cache.go
