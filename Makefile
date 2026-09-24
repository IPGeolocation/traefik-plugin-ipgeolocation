.PHONY: check test vet fmt lint fixtures yaegi try clean

FIXTURES ?= /tmp/ipgeo-fixtures

check: fmt vet test yaegi ## Everything CI runs

test: ## Unit tests, including MMDB fixtures built byte by byte
	go test -race -cover ./...

vet:
	go vet ./...

fmt:
	gofmt -l -d .
	@test -z "$$(gofmt -l .)" || (echo "run gofmt -w ." && exit 1)

lint: ## Requires golangci-lint
	golangci-lint run

fixtures: ## Write small sample databases to $(FIXTURES)
	@mkdir -p $(FIXTURES)
	IPGEO_FIXTURE_OUT=$(FIXTURES) go test -run TestWriteFixtureDatabase ./... > /dev/null
	@echo "sample databases written to $(FIXTURES)"

yaegi: fixtures ## Load the plugin through Yaegi, the interpreter Traefik uses
	cd test/yaegi && go run . ../.. $(FIXTURES)

try: ## End to end inside a real Traefik binary (downloads it, no Docker needed)
	./scripts/try-it.sh

clean:
	rm -rf $(FIXTURES) .local-test
