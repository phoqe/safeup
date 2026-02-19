VERSION ?= dev

.PHONY: build release test

test:
	./scripts/test-docker.sh

build:
	GOOS=linux GOARCH=amd64 go build -ldflags "-X github.com/phoqe/safeup/cmd.Version=$(VERSION)" -o safeup-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags "-X github.com/phoqe/safeup/cmd.Version=$(VERSION)" -o safeup-linux-arm64 .

release: build
	@echo "Built safeup-linux-amd64 and safeup-linux-arm64"
	@echo "Tag and push: git tag vX.Y.Z && git push origin vX.Y.Z"
