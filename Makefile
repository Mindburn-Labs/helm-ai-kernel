.PHONY: build test test-race test-sdk-ts test-design-system test-sdk-py test-sdk-rust test-sdk-java verify-fixtures verify-presentation test-all bench bench-report lint crucible proxy docker docker-up sbom vex provenance onboard demo-cli mcp-pack mcp-install release-binaries release-binaries-reproducible release-all verify-boundary verify-cosign bench-pin codegen codegen-go codegen-python codegen-ts codegen-java codegen-rust codegen-check clean docs-coverage docs-truth

VERSION ?= $(shell cat VERSION 2>/dev/null || echo 0.4.0)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT) -X main.buildTime=$(BUILD_TIME)

build:
	cd core && go build -ldflags "$(LDFLAGS)" -o ../bin/helm ./cmd/helm/

test:
	cd core && go test ./pkg/... -count=1

test-race:
	cd core && go test ./pkg/... -count=1 -race

test-sdk-ts:
	cd sdk/ts && npm ci && npm test -- --run && npm run build

test-design-system:
	cd packages/design-system-core && npm ci && npm run typecheck && npm test && npm run build && npm run smoke && npm run pack:dry

test-sdk-py:
	cd sdk/python && python -m pip install -q '.[dev]' && pytest -v --tb=short

test-sdk-rust:
	cd sdk/rust && cargo test

test-sdk-java:
	cd sdk/java && mvn -q test

verify-fixtures:
	cd core && go test ./pkg/verifier -run TestVerifyBundle_GoldenFixtureRoots -count=1

verify-presentation:
	bash tools/verify-presentation.sh

test-all: test test-sdk-py test-sdk-ts test-design-system test-sdk-rust test-sdk-java verify-fixtures

bench:
	cd core && go test -bench=. -benchmem -count=3 ./pkg/crypto/ ./pkg/store/ ./pkg/guardian/ ./benchmarks/

bench-report:
	cd core && go test -v -run TestOverheadReport -count=1 ./benchmarks/

lint: docs-coverage docs-truth
	cd core && go vet ./...
	cd core && test -z "$$(gofmt -l .)" || (echo "Run gofmt -w ." && exit 1)

crucible: build
	bash scripts/usecases/run_all.sh

proxy: build
	./bin/helm proxy --upstream https://api.openai.com/v1

docker:
	docker build -t ghcr.io/mindburn-labs/helm-oss:local .

docker-up:
	docker compose up -d

sbom: build
	bash scripts/ci/generate_sbom.sh

provenance:
	cd core && CGO_ENABLED=0 go build -ldflags="-s -w \
		-X main.version=$(VERSION) \
		-X main.commit=$$(git rev-parse HEAD) \
		-X main.buildTime=$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		-o ../bin/helm ./cmd/helm/
	shasum -a 256 bin/helm > bin/helm.sha256

onboard: build
	./bin/helm onboard --yes

demo-cli: build
	./bin/helm demo organization --template starter --provider mock

mcp-pack: build
	@mkdir -p dist
	./bin/helm mcp pack --client claude-desktop --out dist/helm.mcpb

mcp-install: build
	./bin/helm mcp install --client claude-code

RELEASE_LDFLAGS := -s -w $(LDFLAGS)

release-binaries:
	@mkdir -p bin
	cd core && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(RELEASE_LDFLAGS)" -o ../bin/helm-linux-amd64 ./cmd/helm/
	cd core && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(RELEASE_LDFLAGS)" -o ../bin/helm-linux-arm64 ./cmd/helm/
	cd core && GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(RELEASE_LDFLAGS)" -o ../bin/helm-darwin-amd64 ./cmd/helm/
	cd core && GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(RELEASE_LDFLAGS)" -o ../bin/helm-darwin-arm64 ./cmd/helm/
	cd core && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(RELEASE_LDFLAGS)" -o ../bin/helm-windows-amd64.exe ./cmd/helm/
	cd bin && shasum -a 256 helm-* > SHA256SUMS.txt

release-all: release-binaries sbom mcp-pack

# --- Reproducibility & Cosign & VEX (Workstream E) -----------------------
# SOURCE_DATE_EPOCH defaults to the HEAD commit timestamp so local devs and
# CI produce byte-identical artifacts when invoked at the same revision.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || date -u +%s)
REPRO_BUILD_TIME := $(shell { date -u -r $(SOURCE_DATE_EPOCH) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$(SOURCE_DATE_EPOCH)" +%Y-%m-%dT%H:%M:%SZ; })
REPRO_LDFLAGS := -s -w -buildid= -X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT) -X main.buildTime=$(REPRO_BUILD_TIME)
REPRO_GOFLAGS := -trimpath -buildvcs=false

release-binaries-reproducible:
	@mkdir -p bin
	@echo "Reproducible build: SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) BUILD_TIME=$(REPRO_BUILD_TIME)"
	cd core && SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build $(REPRO_GOFLAGS) -ldflags="$(REPRO_LDFLAGS)" -o ../bin/helm-linux-amd64       ./cmd/helm/
	cd core && SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build $(REPRO_GOFLAGS) -ldflags="$(REPRO_LDFLAGS)" -o ../bin/helm-linux-arm64       ./cmd/helm/
	cd core && SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build $(REPRO_GOFLAGS) -ldflags="$(REPRO_LDFLAGS)" -o ../bin/helm-darwin-amd64      ./cmd/helm/
	cd core && SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build $(REPRO_GOFLAGS) -ldflags="$(REPRO_LDFLAGS)" -o ../bin/helm-darwin-arm64      ./cmd/helm/
	cd core && SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(REPRO_GOFLAGS) -ldflags="$(REPRO_LDFLAGS)" -o ../bin/helm-windows-amd64.exe ./cmd/helm/
	cd bin && shasum -a 256 helm-* > SHA256SUMS.txt

# Generate OpenVEX statements for every CVE listed in the current SBOM.
vex:
	@bash scripts/release/generate_vex.sh

# Verify the cosign signature of a local artifact tree (smoke / docs example).
verify-cosign:
	@bash scripts/release/verify_cosign.sh

# Pin the latest benchmark report to a per-release file under benchmarks/results/.
bench-pin:
	@bash scripts/release/pin_benchmarks.sh "$(VERSION)"

PROTO_DIR := protocols/proto
PROTO_FILES := $(shell find $(PROTO_DIR) -name '*.proto' 2>/dev/null)

codegen: codegen-go codegen-python codegen-ts codegen-java codegen-rust

codegen-go:
	@mkdir -p sdk/go/gen/kernelv1
	protoc --go_out=sdk/go/gen --go-grpc_out=sdk/go/gen \
		--go_opt=paths=source_relative --go-grpc_opt=paths=source_relative \
		-I$(PROTO_DIR) $(PROTO_FILES)

codegen-python:
	@mkdir -p sdk/python/helm_sdk/generated
	python -m grpc_tools.protoc --python_out=sdk/python/helm_sdk/generated \
		--grpc_python_out=sdk/python/helm_sdk/generated \
		--pyi_out=sdk/python/helm_sdk/generated \
		-I$(PROTO_DIR) $(PROTO_FILES)

codegen-ts:
	@mkdir -p sdk/ts/src/generated
	cd sdk/ts && npm ci
	protoc --plugin=./sdk/ts/node_modules/.bin/protoc-gen-ts_proto \
		--ts_proto_out=sdk/ts/src/generated \
		--ts_proto_opt=outputServices=grpc-js \
		-I$(PROTO_DIR) $(PROTO_FILES)

codegen-java:
	@mkdir -p sdk/java/src/main/java
	protoc --java_out=sdk/java/src/main/java \
		-I$(PROTO_DIR) $(PROTO_FILES)

codegen-rust:
	cd sdk/rust && cargo build --features codegen

codegen-check: codegen
	@git diff --exit-code sdk/ || (echo "SDK types are out of sync. Run 'make codegen'." && exit 1)

verify-boundary:
	bash tools/verify-boundary.sh

clean:
	rm -rf bin/ dist/ sbom.json deps.txt helm-mcp-plugin/ benchmarks/results/*.json

.PHONY: docs-coverage docs-truth

docs-coverage:
	python3 scripts/check_documentation_coverage.py

docs-truth:
	python3 scripts/check_documentation_truth.py
