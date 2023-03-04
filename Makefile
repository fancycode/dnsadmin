BINARY=bin/dnsadmin
SOURCES=$(wildcard *.go)

all: $(BINARY)

format:
	go fmt $(SOURCES)

$(BINARY): $(SOURCES)
	go build -o $(BINARY) $(SOURCES)
