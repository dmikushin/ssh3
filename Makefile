GOOS?=linux
BUILDFLAGS ?=-ldflags "-X main.version=$(shell git describe --tags --always --dirty) -X main.buildDate=$(shell date +%Y-%m-%d)"

GO_OPTS?=CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS)
GO_TAGS?=
TEST_OPTS?=GOOS=$(GOOS) GOARCH=$(GOARCH)

lint:
	go fmt ./...
	# FIXME: fix vet errors before turning this on
	# go vet ./...

test:
	$(TEST_OPTS) go test ./...
	$(TEST_OPTS) go run github.com/onsi/ginkgo/v2/ginkgo -r

integration-tests:
	CERT_PEM=$(CERT_PEM) \
		CERT_PRIV_KEY=$(CERT_PRIV_KEY) \
		ATTACKER_PRIVKEY=$(ATTACKER_PRIVKEY) \
		TESTUSER_PRIVKEY=$(TESTUSER_PRIVKEY) \
		TESTUSER_ED25519_PRIVKEY=$(TESTUSER_ED25519_PRIVKEY) \
		TESTUSER_ECDSA_PRIVKEY=$(TESTUSER_ECDSA_PRIVKEY) \
		TESTUSER_USERNAME=$(TESTUSER_USERNAME) \
		CC=$(CC) \
		CGO_ENABLED=1 \
		GOOS=$(GOOS) \
		SSH3_INTEGRATION_TESTS_WITH_SERVER_ENABLED=1 \
		go run github.com/onsi/ginkgo/v2/ginkgo ./integration_tests

# local-integration-tests runs the full Ginkgo suite end-to-end on the
# current host: it generates the TLS material, SSH key pairs and test
# users itself (the standard `integration-tests` target above assumes
# the caller has already exported all the env vars and set up the
# world).  Requires sudo, openssl, ssh-keygen, useradd; see
# scripts/run_integration_tests.sh for the full contract and the
# environment variables you can override.
local-integration-tests:
	bash scripts/run_integration_tests.sh

# docker-smoke-tests runs a low-risk end-to-end smoke check (echo +
# reverse-tcp through a real ssh3 client<->ssh3 server pair) inside
# a docker-compose stack on an `internal: true` bridge.  Does NOT
# touch host networking, does NOT useradd, does NOT need sudo.  Build
# happens inside the containers, so the first run takes a few minutes
# while the go modules are fetched and the binaries compiled; the
# `tests` service exits non-zero on failure.  Teardown runs even when
# the tests fail so the local docker state stays clean.
#
# Override SSH3_SRC if you want the containers to build against a
# different ssh3 checkout (default: the repo root, i.e. ../.. from
# the compose file):
#   SSH3_SRC=/path/to/fork make docker-smoke-tests
docker-smoke-tests:
	cd integration_tests/docker && \
		./bootstrap.sh && \
		docker compose up -d --build server && \
		( docker compose --profile tests run --build --rm tests; \
		  rc=$$?; \
		  docker compose down --rmi local -v; \
		  exit $$rc )

install:
	$(GO_OPTS) go install $(BUILDFLAGS) ./cmd/ssh3
	$(GO_OPTS) go install $(BUILDFLAGS) ./cmd/ssh3-server

build: client server

client:
	$(GO_OPTS) go build -tags "$(GO_TAGS)" $(BUILD_FLAGS) -o bin/client ./cmd/ssh3/

server:
	$(GO_OPTS) go build -tags "$(GO_TAGS)" $(BUILD_FLAGS) -o bin/server ./cmd/ssh3-server/
