all: build

build: clean cmd/plugin/vault-auth-spire.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o vault-auth-spire cmd/plugin/vault-auth-spire.go

test: build
	cd tests; ln -sf vault-auth-spire.filesource.json vault/config/vault-auth-spire.json; ./integration.bats
	cd tests; ln -sf vault-auth-spire.workloadapi.json vault/config/vault-auth-spire.json; ./integration.bats

clean:
	@rm -f vault-auth-spire
