all: nsregd nsregc


nsregd: nsregd.go
	go build nsregd.go

nsregc: nsregc.go
	go build nsregc.go
