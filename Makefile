.PHONY: build test test-cli test-race test-approval-ceremony test-approval-ceremony-postgres test-connector-release-authority-postgres test-effect-reservation-postgres verify-approval-ceremony-vectors verify-connector-release-authority-vectors verify-effect-close-vectors verify-effect-disposition-vectors verify-boundary-profile-vectors verify-update-bundle-vectors test-sdk-go-standalone test-sdk-ts test-platform test-sdk-py test-sdk-rust test-sdk-java sdk-openapi-check sdk-examples-smoke verify-fixtures verify-presentation tee-collateral-verify test-all bench bench-report lint proto-lint proto-breaking openapi-breaking docker-verify release-readiness crucible proxy docker docker-up docker-smoke compose-smoke helm-chart-smoke kind-smoke deployment-smoke release-smoke version-drift version-drift-report version-drift-published version-status prepare-version sbom vex provenance onboard demo-cli mcp-pack mcp-install release-binaries release-binaries-reproducible release-assets build-release release-all verify-boundary verify-cosign bench-pin codegen codegen-go codegen-python codegen-ts codegen-java codegen-rust codegen-check quality-pr quality-merge quality-release quality-nightly quality-list quality-explain quality-self-test quality-typecheck quality-contracts quality-security quality-runbooks quality-mutation quality-flake quality-impact clean docs-coverage docs-truth launch-record-assets real-use-assets launch-release-dry-run launch-ready conformance-release-report conformance-release-gate

# VERSION is source-controlled release truth. Tag-triggered workflows must
# check that GITHUB_REF_NAME equals v$(VERSION) before any publish step.
VERSION ?= $(shell cat VERSION 2>/dev/null || echo 0.0.0-dev)
PREPARE_VERSION := $(if $(filter command line,$(origin VERSION)),$(VERSION),$(RELEASE_VERSION))
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT) -X main.buildTime=$(BUILD_TIME)
QUALITY := python3 scripts/ci/quality.py
PYTHON ?= python3

build:
	cd core && go build -ldflags "$(LDFLAGS)" -o ../bin/helm-ai-kernel ./cmd/helm-ai-kernel/
	cp bin/helm-ai-kernel bin/helm

test:
	cd core && go test ./pkg/... ./cmd/release-permit-verify/... -count=1

test-cli:
	cd core && go test ./cmd/helm-ai-kernel ./cmd/release-permit-verify -count=1

test-race:
	cd core && go test ./pkg/... -count=1 -race

test-approval-ceremony:
	cd core && go test -race ./pkg/boundary/approvalceremony -count=1

test-approval-ceremony-postgres:
	@test -n "$$HELM_TEST_POSTGRES_URL" || (echo "HELM_TEST_POSTGRES_URL is required" && exit 2)
	cd core && go test -race ./pkg/boundary/approvalceremony -run TestPostgresLifecycleSingleIssueAndConsume -count=10

test-connector-release-authority-postgres:
	@test -n "$$HELM_TEST_POSTGRES_URL" || (echo "HELM_TEST_POSTGRES_URL is required" && exit 2)
	cd core && go test -race ./pkg/registry/connectors -run TestPostgresReleaseAuthorityAppendOnlyCurrentStateAndIsolation -count=10

test-effect-reservation-postgres:
	@test -n "$$HELM_TEST_POSTGRES_URL" || (echo "HELM_TEST_POSTGRES_URL is required" && exit 2)
	cd core && go test -race ./pkg/boundary/approvalceremony -run TestPostgresEffectReservationOrdersFenceRevocationAndLifecycle -count=10

verify-approval-ceremony-vectors:
	cd core && go test ./pkg/boundary/approvalverify -run TestApprovalReferencePackMatchesGoImplementation -count=1
	cd core && go test ./pkg/boundary/approvalceremony -run TestApprovalCeremonyGoldenVectors -count=1
	cd core && go test ./pkg/boundary/approvalceremony -run TestApprovalConsumptionReferencePackMatchesGoImplementation -count=1
	cd core && go test ./pkg/boundary/approvalceremony -run TestApprovalDispatchAdmissionReferencePackMatchesGoImplementation -count=1
	python3 reference_packs/approval/verify_approval_vectors.py
	python3 reference_packs/approval-consumption-v1/verify_vectors.py
	python3 reference_packs/approval-dispatch-admission-v1/verify_vectors.py

verify-connector-release-authority-vectors:
	cd core && go test ./pkg/registry/connectors -run 'TestConnectorReleaseAuthority(ReferencePackMatchesGoImplementation|Schemas)' -count=1
	python3 reference_packs/connector-release-authority-v1/verify_vectors.py

verify-effect-close-vectors:
	cd core && go test ./pkg/boundary/approvalceremony -run 'TestEffectClose(ReferencePackMatchesGoImplementation|Schemas)' -count=1
	python3 reference_packs/effect-close-v1/verify_vectors.py

verify-effect-disposition-vectors:
	cd core && go test ./pkg/contracts -run '^TestEffectDisposition' -count=1
	cd core && go test ./pkg/boundary/approvalceremony -run '^TestEffectDisposition' -count=1
	python3 reference_packs/effect-disposition-v1/verify_vectors.py

verify-boundary-profile-vectors:
	cd core && go test ./pkg/boundary/profile -run 'TestBoundaryProfile(ReferencePackMatchesGoImplementation|Schemas)' -count=1
	python3 reference_packs/boundary-profile-v1/verify_vectors.py

verify-update-bundle-vectors:
	cd core && go test ./pkg/boundary/profile/updatebundle -run TestUpdateBundleReferencePackMatchesGoImplementation -count=1
	cd core && go test ./pkg/boundary/profile -run TestUpdateBundleManifestSchema -count=1
	python3 reference_packs/update-bundle-v1/verify_vectors.py

test-sdk-go-standalone:
	cd sdk/go && GOWORK=off go test ./...

test-sdk-ts:
	cd sdk/ts && npm ci && npm test -- --run && npm run build

test-sdk-py:
	cd sdk/python && python -m pip install -q '.[dev]' && pytest -v --tb=short

test-sdk-rust:
	cd sdk/rust && CARGO_HTTP_MULTIPLEXING=false cargo test

test-sdk-java:
	cd sdk/java && mvn -q test

sdk-openapi-check:
	bash scripts/sdk/openapi_check.sh

sdk-examples-smoke:
	bash scripts/sdk/examples_smoke.sh

verify-fixtures:
	cd core && go test ./pkg/verifier -run TestVerifyBundle_GoldenFixtureRoots -count=1
	cd core && go test ./pkg/boundary/extauthz -run TestContract -count=1
	cd core && go test ./pkg/canonicalize -run TestExtauthzGoldenVectorsAreCanonical -count=1
	cd core && go test ./pkg/boundary/approvalverify -run TestApprovalReferencePackMatchesGoImplementation -count=1
	$(MAKE) verify-approval-ceremony-vectors
	$(MAKE) verify-connector-release-authority-vectors
	$(MAKE) verify-effect-close-vectors
	$(MAKE) verify-effect-disposition-vectors
	$(MAKE) verify-boundary-profile-vectors
	$(MAKE) verify-update-bundle-vectors
	python3 reference_packs/extauthz/verify_extauthz_vectors.py
	python3 reference_packs/approval/verify_approval_vectors.py
	protoc -Iprotocols/proto --descriptor_set_out="$${TMPDIR:-/tmp}/helm-extauthz-v1.pb" protocols/proto/boundary/extauthz/v1/extauthz.proto

tee-collateral-verify:
	cd core && go test ./pkg/crypto/tee/collateral -count=1 && go run ./cmd/tee-collateral -bundle pkg/crypto/tee/collateral/testdata/offline_bundle.json

verify-presentation:
	bash tools/verify-presentation.sh

test-all: test test-sdk-py test-sdk-ts test-sdk-rust test-sdk-java verify-fixtures

test-platform: test verify-fixtures docs-coverage docs-truth

bench:
	cd core && go test -bench=. -benchmem -count=3 ./pkg/crypto/ ./pkg/store/ ./pkg/guardian/ ./benchmarks/

bench-report:
	cd core && go test -v -run TestOverheadReport -count=1 ./benchmarks/

lint: docs-coverage docs-truth
	cd core && go vet ./...
	cd core && test -z "$$(gofmt -l .)" || (echo "Run gofmt -w ." && exit 1)

proto-lint:
	buf lint protocols/policy-schema

proto-breaking:
	bash scripts/ci/contract_breaking.sh proto

openapi-breaking:
	bash scripts/ci/contract_breaking.sh openapi

docker-verify:
	docker build -f Dockerfile -t helm-ai-kernel:verify-root .
	docker build -f Dockerfile.slim -t helm-ai-kernel:verify-slim .
	docker build -f core/Dockerfile -t helm-ai-kernel:verify-core core
	docker build -f core/Dockerfile.api -t helm-ai-kernel:verify-core-api .
	docker build -f oss-fuzz/Dockerfile -t helm-ai-kernel:verify-oss-fuzz oss-fuzz

release-readiness: version-drift verify-boundary docs-truth test-sdk-go-standalone proto-lint proto-breaking docker-verify conformance-release-gate deployment-smoke release-smoke
	@echo "✅ Release readiness gate passed"

crucible: build
	bash scripts/usecases/run_all.sh

proxy: build
	./bin/helm-ai-kernel proxy --upstream http://127.0.0.1:19090/v1

docker: build
	docker build \
		--build-arg BUILD_VERSION=$(VERSION) \
		--build-arg BUILD_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t ghcr.io/mindburn-labs/helm-ai-kernel:local .

docker-up:
	docker compose up -d

docker-smoke: docker
	bash scripts/ci/docker_smoke.sh

compose-smoke: docker
	bash scripts/ci/docker_smoke.sh --compose

helm-chart-smoke:
	bash scripts/ci/helm_chart_smoke.sh

kind-smoke: docker
	bash scripts/ci/kind_smoke.sh

deployment-smoke: docker-smoke compose-smoke helm-chart-smoke

release-smoke:
	bash scripts/ci/release_smoke.sh

version-drift:
	python3 scripts/release/check_version_drift.py local

version-drift-report:
	python3 scripts/release/check_version_drift.py --report --write-status version-status.json local

version-drift-published:
	python3 scripts/release/check_version_drift.py published

version-status:
	python3 scripts/release/check_version_drift.py --report --write-status version-status.json published

prepare-version:
	@test -n "$(PREPARE_VERSION)" || (echo "Usage: make prepare-version VERSION=0.5.6" && exit 2)
	python3 scripts/release/prepare_version.py "$(PREPARE_VERSION)"

quality-pr:
	$(QUALITY) run pr --impact

quality-merge:
	$(QUALITY) run merge

quality-release:
	$(QUALITY) run release --strict

quality-nightly:
	$(QUALITY) run nightly

quality-list:
	$(QUALITY) list

quality-explain:
	@test -n "$(CHECK)" || (echo "Usage: make quality-explain CHECK=<gate-id>" && exit 2)
	$(QUALITY) explain "$(CHECK)"

quality-self-test:
	$(QUALITY) self-test

quality-typecheck:
	$(QUALITY) run typecheck

quality-contracts:
	$(QUALITY) run contracts

quality-security:
	$(QUALITY) run security

# quantum_posture: this target runs a source annotation guard only.
quantum-crypto-inventory:
	$(PYTHON) scripts/ci/check_quantum_crypto_inventory.py

quality-runbooks:
	$(QUALITY) run runbooks

quality-mutation:
	$(QUALITY) run mutation

quality-flake:
	$(QUALITY) run flake

quality-impact:
	$(QUALITY) run impact --impact

sbom: build
	HELM_VERSION=$(VERSION) bash scripts/ci/generate_sbom.sh

provenance:
	cd core && CGO_ENABLED=0 go build -ldflags="-s -w \
		-X main.version=$(VERSION) \
		-X main.commit=$$(git rev-parse HEAD) \
		-X main.buildTime=$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		-o ../bin/helm-ai-kernel ./cmd/helm-ai-kernel/
	shasum -a 256 bin/helm-ai-kernel > bin/helm-ai-kernel.sha256

onboard: build
	./bin/helm-ai-kernel onboard --yes

demo-cli: build
	./bin/helm-ai-kernel demo organization --template starter --provider mock

demo-local: build
	bash scripts/launch/demo-local.sh

demo-proof: build
	bash scripts/launch/demo-proof.sh

demo-mcp: build
	bash scripts/launch/demo-mcp.sh

demo-openai-proxy: build
	bash scripts/launch/demo-openai-proxy.sh

launch-smoke:
	bash scripts/launch/smoke.sh

launch-record-assets:
	bash scripts/launch/record-assets.sh

real-use-assets:
	bash scripts/record-real-use-assets.sh

launch-release-dry-run:
	bash scripts/release/dry_run.sh

launch-ready:
	bash scripts/launch/launch-ready.sh --write

conformance-release-report: build
	bash scripts/release/prepare_conformance_release_inputs.sh
	./bin/helm-ai-kernel conform --profile SMB --gate G0 --signed --output artifacts/conformance

conformance-release-gate:
	@if [ -z "$$HELM_CONFORMANCE_REPORT" ]; then $(MAKE) conformance-release-report; fi
	bash scripts/release/conformance_release_gate.sh

mcp-pack: build
	@mkdir -p dist
	./bin/helm-ai-kernel mcp pack --client claude-desktop --out dist/helm-ai-kernel.mcpb

mcp-install: build
	./bin/helm-ai-kernel mcp install --client claude-code

RELEASE_LDFLAGS := -s -w $(LDFLAGS)

release-binaries:
	@mkdir -p bin
	cd core && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(RELEASE_LDFLAGS)" -o ../bin/helm-ai-kernel-linux-amd64 ./cmd/helm-ai-kernel/
	cd core && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(RELEASE_LDFLAGS)" -o ../bin/helm-ai-kernel-linux-arm64 ./cmd/helm-ai-kernel/
	cd core && GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(RELEASE_LDFLAGS)" -o ../bin/helm-ai-kernel-darwin-amd64 ./cmd/helm-ai-kernel/
	cd core && GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(RELEASE_LDFLAGS)" -o ../bin/helm-ai-kernel-darwin-arm64 ./cmd/helm-ai-kernel/
	cd core && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(RELEASE_LDFLAGS)" -o ../bin/helm-ai-kernel-windows-amd64.exe ./cmd/helm-ai-kernel/
	cp bin/helm-ai-kernel-linux-amd64 bin/helm-linux-amd64
	cp bin/helm-ai-kernel-linux-arm64 bin/helm-linux-arm64
	cp bin/helm-ai-kernel-darwin-amd64 bin/helm-darwin-amd64
	cp bin/helm-ai-kernel-darwin-arm64 bin/helm-darwin-arm64
	cp bin/helm-ai-kernel-windows-amd64.exe bin/helm-windows-amd64.exe
	cd bin && shasum -a 256 helm-ai-kernel-* helm-linux-* helm-darwin-* helm-windows-* > SHA256SUMS.txt

release-assets: release-binaries-reproducible mcp-pack sbom vex
	bash scripts/release/stage_release_assets.sh

build-release: release-assets

release-all: release-assets

# --- Reproducibility & Cosign & VEX (Workstream E) -----------------------
# SOURCE_DATE_EPOCH defaults to the HEAD commit timestamp so local devs and
# CI produce byte-identical artifacts when invoked at the same revision.
SOURCE_DATE_EPOCH_ORIGIN := $(origin SOURCE_DATE_EPOCH)
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || date -u +%s)
VEX_FILE := release/vex/v$(VERSION).openvex.json
VEX_SOURCE_DATE_EPOCH := $(if $(filter undefined,$(SOURCE_DATE_EPOCH_ORIGIN)),$(shell python3 -c 'import datetime,json,sys; data=json.load(open(sys.argv[1])); print(int(datetime.datetime.fromisoformat(data["timestamp"].replace("Z","+00:00")).timestamp()))' "$(VEX_FILE)" 2>/dev/null || printf '%s' "$(SOURCE_DATE_EPOCH)"),$(SOURCE_DATE_EPOCH))
REPRO_BUILD_TIME := $(shell { date -u -r $(SOURCE_DATE_EPOCH) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$(SOURCE_DATE_EPOCH)" +%Y-%m-%dT%H:%M:%SZ; })
REPRO_LDFLAGS := -s -w -buildid= -X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT) -X main.buildTime=$(REPRO_BUILD_TIME)
REPRO_GOFLAGS := -trimpath -buildvcs=false

release-binaries-reproducible:
	@mkdir -p bin
	@echo "Reproducible build: SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) BUILD_TIME=$(REPRO_BUILD_TIME)"
	cd core && SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build $(REPRO_GOFLAGS) -ldflags="$(REPRO_LDFLAGS)" -o ../bin/helm-ai-kernel-linux-amd64       ./cmd/helm-ai-kernel/
	cd core && SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build $(REPRO_GOFLAGS) -ldflags="$(REPRO_LDFLAGS)" -o ../bin/helm-ai-kernel-linux-arm64       ./cmd/helm-ai-kernel/
	cd core && SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build $(REPRO_GOFLAGS) -ldflags="$(REPRO_LDFLAGS)" -o ../bin/helm-ai-kernel-darwin-amd64      ./cmd/helm-ai-kernel/
	cd core && SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build $(REPRO_GOFLAGS) -ldflags="$(REPRO_LDFLAGS)" -o ../bin/helm-ai-kernel-darwin-arm64      ./cmd/helm-ai-kernel/
	cd core && SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(REPRO_GOFLAGS) -ldflags="$(REPRO_LDFLAGS)" -o ../bin/helm-ai-kernel-windows-amd64.exe ./cmd/helm-ai-kernel/
	cp bin/helm-ai-kernel-linux-amd64 bin/helm-linux-amd64
	cp bin/helm-ai-kernel-linux-arm64 bin/helm-linux-arm64
	cp bin/helm-ai-kernel-darwin-amd64 bin/helm-darwin-amd64
	cp bin/helm-ai-kernel-darwin-arm64 bin/helm-darwin-arm64
	cp bin/helm-ai-kernel-windows-amd64.exe bin/helm-windows-amd64.exe
	cd bin && shasum -a 256 helm-ai-kernel-* helm-linux-* helm-darwin-* helm-windows-* > SHA256SUMS.txt

# Generate OpenVEX statements for every CVE listed in the current SBOM.
vex:
	@SOURCE_DATE_EPOCH=$(VEX_SOURCE_DATE_EPOCH) HELM_VERSION=$(VERSION) bash scripts/release/generate_vex.sh

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
	cd sdk/rust && CARGO_HTTP_MULTIPLEXING=false cargo build --features codegen

codegen-check: codegen
	@git diff --exit-code -- \
		sdk/go/gen \
		sdk/python/helm_sdk/generated \
		sdk/ts/src/generated \
		sdk/java/src/main/java/helm \
		sdk/rust/src/generated \
		|| (echo "Generated SDK bindings are out of sync. Run 'make codegen'." && exit 1)

verify-boundary:
	bash tools/verify-boundary.sh

clean:
	rm -rf bin/ dist/ sbom.json deps.txt helm-mcp-plugin/ benchmarks/results/*.json

.PHONY: docs-coverage docs-truth

docs-coverage:
	python3 scripts/check_documentation_coverage.py

docs-truth:
	python3 scripts/check_documentation_truth.py

.PHONY: launchpad-promotion-check
launchpad-promotion-check:
	cd core && go run ./cmd/helm-ai-kernel launch promote --apps openclaw,hermes --sync-derived --check
