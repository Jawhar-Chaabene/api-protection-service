SHELL := /bin/sh

.PHONY: proto build run-gateway run-security test test-integration docker-up docker-down

proto:
	go run github.com/bufbuild/buf/cmd/buf@latest generate proto

build:
	go build ./...

run-gateway:
	go run ./cmd/gateway

run-security:
	go run ./cmd/security-service

test:
	go test ./...

test-integration:
	go test ./tests -v

docker-up:
	docker compose -f infra/docker-compose.yml up --build -d

docker-down:
	docker compose -f infra/docker-compose.yml down -v
