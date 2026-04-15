.PHONY: build test test-race test-sdk-ts test-sdk-py test-all test-a2a test-otel test-l3 test-owasp crucible crucible-full lint proxy clean docker demo demo-down release-binaries verify-boundary onboard demo-cli mcp-pack mcp-install release-all operator-crds bench bench-report

VERSION ?= $(shell cat VERSION 2>/dev/null || echo 0.3.0)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT) -X main.buildTime=$(BUILD_TIME)

build:
	cd core && go build -ldflags "$(LDFLAGS)" -o ../bin/helm ./cmd/helm/
	@echo "✅ bin/helm v$(VERSION) ($(GIT_COMMIT))"

# ── Test ───────────────────────────────────────────────
test:
	cd core && go test ./pkg/... -count=1

test-race:
	cd core && go test ./pkg/... -count=1 -race

test-sdk-ts:
	cd sdk/ts && npm test -- --run

test-sdk-py:
	cd sdk/python && pip install -q '.[dev]' && pytest -v --tb=short --cov=helm_sdk --cov-report=term-missing --cov-fail-under=80

test-cli:
	cd packages/mindburn-helm-cli && npm test -- --run

verify-fixtures:
	@echo "Verifying golden fixtures..."
	@cd packages/mindburn-helm-cli && npx tsx ../../scripts/verify-fixture-roots.mts
	@echo "Golden fixture roots verified"

test-all: test test-sdk-ts test-sdk-py test-cli verify-fixtures

# ── Benchmarks ─────────────────────────────────────────
bench:
	cd core && go test -bench=. -benchmem -count=3 ./pkg/crypto/ ./pkg/store/ ./pkg/guardian/ ./benchmarks/
	@echo "✅ Benchmarks complete"

bench-report:
	cd core && go test -v -run TestOverheadReport -count=1 ./benchmarks/
	@echo "✅ Overhead report: benchmarks/results/latest.json"

# ── Strategic Test Targets ──────────────────────────────────
test-a2a:
	cd core && go test ./pkg/a2a/... -v -count=1

test-otel:
	cd core && go test ./pkg/otel/... -v -count=1

test-l3:
	cd core && go test ./pkg/conformance/... -v -count=1 -run "TestL3|L3-"

test-owasp:
	cd core && go test ./pkg/conformance/... -v -count=1 -run "TestOWASP"

# ── Crucible (adversarial + conformance + use cases) ──
crucible: test
	bash scripts/usecases/run_all.sh
	@echo "✅ Crucible passed"

crucible-full: test test-a2a test-otel test-l3
	bash scripts/usecases/run_all.sh
	@echo "✅ Full Crucible passed (incl. L3 + A2A + OTel)"

# ── Kubernetes Operator ───────────────────────────────
operator-crds:
	kubectl apply -f deploy/helm-operator/config/crd/helm-crds.yaml
	@echo "✅ CRDs applied"

# ── Lint ───────────────────────────────────────────────
lint:
	cd core && go vet ./...

# ── Proxy (quick-start) ───────────────────────────────
proxy: build
	./bin/helm proxy --upstream https://api.openai.com/v1

# ── Docker ─────────────────────────────────────────────
docker:
	docker build -t helm:latest .

docker-up:
	docker compose up -d

# ── Demo (DigitalOcean / any Docker host) ──────────────
demo:
	docker compose -f docker-compose.demo.yml up -d --build
	@echo ""
	@echo "✅ HELM demo running"
	@echo "   API:    http://localhost:8080"
	@echo "   Health: http://localhost:8080/healthz"
	@echo ""

demo-down:
	docker compose -f docker-compose.demo.yml down

demo-reset:
	bash deploy/demo-reset.sh

# ── SBOM ───────────────────────────────────────────────
sbom: build
	bash scripts/ci/generate_sbom.sh
	@echo "✅ sbom.json (CycloneDX) + deps.txt generated"

# ── Provenance ─────────────────────────────────────────
provenance:
	cd core && CGO_ENABLED=0 go build -ldflags="-s -w \
		-X main.version=$(VERSION) \
		-X main.commit=$$(git rev-parse HEAD) \
		-X main.buildTime=$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		-o ../bin/helm ./cmd/helm/
	shasum -a 256 bin/helm > bin/helm.sha256
	@echo "✅ Provenance build: bin/helm + bin/helm.sha256"

# ── Release Binaries (cross-compile) ──────────────────
RELEASE_LDFLAGS := -s -w $(LDFLAGS)

release-binaries:
	@echo "Building release binaries (v$(VERSION))..."
	cd core && GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(RELEASE_LDFLAGS)" -o ../bin/helm-linux-amd64 ./cmd/helm/
	cd core && GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(RELEASE_LDFLAGS)" -o ../bin/helm-linux-arm64 ./cmd/helm/
	cd core && GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(RELEASE_LDFLAGS)" -o ../bin/helm-darwin-amd64 ./cmd/helm/
	cd core && GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(RELEASE_LDFLAGS)" -o ../bin/helm-darwin-arm64 ./cmd/helm/
	cd core && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(RELEASE_LDFLAGS)" -o ../bin/helm-windows-amd64.exe ./cmd/helm/
	cd bin && shasum -a 256 helm-* > SHA256SUMS.txt
	@echo "✅ Release binaries + SHA256SUMS.txt (v$(VERSION))"

# ── Quickstart (one-command onboard + demo) ────────────
onboard: build
	./bin/helm onboard --yes

demo-cli: build
	./bin/helm demo organization --template starter

# ── MCP ────────────────────────────────────────────────
mcp-pack: build
	./bin/helm mcp pack --client claude-desktop --out dist/helm.mcpb
	@echo "✅ dist/helm.mcpb (MCPB bundle)"

mcp-install: build
	./bin/helm mcp install --client claude-code
	@echo "✅ helm-mcp-plugin/ (Claude Code plugin)"

# ── Full Release (all artifacts) ───────────────────────
release-all: release-binaries sbom mcp-pack
	@mkdir -p dist
	cp bin/helm-* dist/
	cp bin/SHA256SUMS.txt dist/
	@echo "✅ Full release in dist/ (binaries + SBOM + MCPB)"

# ── SDK Codegen (proto → all SDKs) ─────────────────────
PROTO_DIR := protocols/proto
PROTO_FILES := $(shell find $(PROTO_DIR) -name '*.proto' 2>/dev/null)

.PHONY: codegen codegen-go codegen-python codegen-ts codegen-java codegen-rust codegen-check

codegen: codegen-go codegen-python codegen-ts codegen-java codegen-rust
	@echo "✅ All SDK types regenerated from proto IDL"

codegen-go:
	@mkdir -p sdk/go/gen/kernelv1
	protoc --go_out=sdk/go/gen --go-grpc_out=sdk/go/gen \
		--go_opt=paths=source_relative --go-grpc_opt=paths=source_relative \
		-I$(PROTO_DIR) $(PROTO_FILES)
	@echo "  → Go types regenerated"

codegen-python:
	@mkdir -p sdk/python/helm_sdk/generated
	python -m grpc_tools.protoc --python_out=sdk/python/helm_sdk/generated \
		--grpc_python_out=sdk/python/helm_sdk/generated \
		--pyi_out=sdk/python/helm_sdk/generated \
		-I$(PROTO_DIR) $(PROTO_FILES)
	@echo "  → Python types regenerated"

codegen-ts:
	@mkdir -p sdk/ts/src/generated
	protoc --plugin=./node_modules/.bin/protoc-gen-ts_proto \
		--ts_proto_out=sdk/ts/src/generated \
		--ts_proto_opt=outputServices=grpc-js \
		-I$(PROTO_DIR) $(PROTO_FILES)
	@echo "  → TypeScript types regenerated"

codegen-java:
	@mkdir -p sdk/java/src/main/java
	protoc --java_out=sdk/java/src/main/java \
		-I$(PROTO_DIR) $(PROTO_FILES)
	@echo "  → Java types regenerated"

codegen-rust:
	cd sdk/rust && cargo build --features codegen 2>/dev/null || echo "  → Rust codegen: run manually (requires tonic-build)"

codegen-check: codegen
	@echo "Checking for SDK type drift..."
	@git diff --exit-code sdk/ || (echo "❌ SDK types are out of sync with proto IDL. Run 'make codegen'." && exit 1)
	@echo "✅ SDK types match proto IDL"

# ── Repo Boundary (OSS ↔ Commercial) ──────────────────
verify-boundary:
	bash tools/verify-boundary.sh
	@echo "✅ All protected paths in sync"

# ── Clean ──────────────────────────────────────────────
clean:
	rm -rf bin/ dist/ sbom.json deps.txt helm-mcp-plugin/
