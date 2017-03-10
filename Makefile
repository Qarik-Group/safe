DESTDIR      ?= /usr/local
RELEASE_ROOT ?= release
TARGETS      ?= linux/amd64 darwin/amd64 windows/amd64

GO_LDFLAGS := -ldflags="-X main.Version=$(VERSION)"

build:
	go build $(GO_LDFLAGS) .
	./safe -v

test: build
	./try

release: build
	mkdir -p $(RELEASE_ROOT)
	@go get github.com/mitchellh/gox
	gox -osarch="$(TARGETS)" --output="$(RELEASE_ROOT)/artifacts/safe-{{.OS}}-{{.Arch}}" $(GO_LDFLAGS)

install: build
	mkdir -p $(DESTDIR)/bin
	cp safe $(DESTDIR)/bin
