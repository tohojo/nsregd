all: nsregd nsregc


nsregd: nsregd.go keydb.go
	go build nsregd.go keydb.go

nsregc: nsregc.go
	go build nsregc.go
