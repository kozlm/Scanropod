.PHONY: build run docker

BINARY=scanropod

build:
	go build -o $(BINARY) ./cmd/server

run: build
	./$(BINARY)

docker:
	docker build -t scanropod:latest .
