.PHONY: build run docker

BINARY=scanropods

build:
	go build -o $(BINARY) ./cmd/server

run: build
	./$(BINARY)

docker:
	docker build -t scanropods:latest .
