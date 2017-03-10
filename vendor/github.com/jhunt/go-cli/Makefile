all:
	go build .

test:
	ginkgo .

cover:
	ginkgo -cover .
	go tool cover -html=go-cli.coverprofile
