all:
	go build .

test:
	go test .

cover:
	go test -cover . -coverprofile snapshot.cover
	go tool cover -html=snapshot.cover
