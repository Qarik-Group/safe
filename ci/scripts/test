#!/bin/bash

set -e

export GOPATH=${PWD}/gopath
export PATH=${PATH}:${GOPATH}/bin
cd ${GOPATH}/src/${MODULE}


go version; echo; echo
go vet $(go list ./... | grep -v vendor)
go test -v ./...
