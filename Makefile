BINARY=bin/dnsadmin
SOURCES=$(wildcard *.go)

export GOPATH=$(shell pwd)/vendor

all: $(BINARY)

deps_bcrypt:
	go get golang.org/x/crypto/bcrypt

deps_mux:
	go get github.com/gorilla/mux

deps_securecookie:
	go get github.com/gorilla/securecookie

deps: \
	deps_bcrypt \
	deps_mux \
	deps_securecookie

format:
	go fmt $(SOURCES)

$(BINARY): deps $(SOURCES)
	go build -o $(BINARY) $(SOURCES)
