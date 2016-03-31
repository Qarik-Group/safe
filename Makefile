DESTDIR      ?= /usr/local
RELEASE_ROOT ?= artifacts
TARGETS      ?= linux/amd64 darwin/amd64

GO_LDFLAGS := -ldflags="-X main.Version=$(VERSION)"

build:
	godep restore
	go build $(GO_LDFLAGS) .
	./safe -v

test:
	@echo "no tests..."

release: build
	mkdir -p $(RELEASE_ROOT)
	@go get github.com/mitchellh/gox
	gox -osarch="$(TARGETS)" --output="$(RELEASE_ROOT)/safe-{{.OS}}-{{.Arch}}" $(GO_LDFLAGS)

install: build
	mkdir -p $(DESTDIR)/bin
	cp safe $(DESTDIR)/bin
