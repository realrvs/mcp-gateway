.PHONY: help build test lint run docker-build helm-lint

help:
@echo "build        - собрать бинарник"
@echo "test         - запустить тесты"
@echo "lint         - запустить линтер"
@echo "run          - запустить локально"
@echo "docker-build - собрать Docker-образ"
@echo "helm-lint    - проверить Helm-чарт"

build:
go build -o bin/gateway ./cmd/gateway

test:
go test -race ./...

lint:
golangci-lint run

run:
go run ./cmd/gateway --config ./configs/local.yaml

docker-build:
docker build -t mcp-gateway:local -f deploy/docker/Dockerfile .

helm-lint:
helm lint deploy/helm/mcp-gateway