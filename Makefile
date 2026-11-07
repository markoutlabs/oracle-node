# price-oracle: build, test, release, deploy. `make help` lists the targets.
#
#   make canister                    # the registry canister wasm, with its .did baked in
#   make test lint                   # what CI runs
#   make network deploy              # the canister on the local network
#   make release                     # reproducible wasm and Linux binaries, in Docker
#   make publish                     # those, and release/install.sh, as a GitHub release
#   make deploy ENV=ic IDENTITY=me   # the release wasm on mainnet, controlled by `me`
#   make deploy ENV=ic IDENTITY=me REPRODUCIBLE=0   # the same, built here without Docker

ENV ?= local
IDENTITY ?=
MODE ?= auto
REPRODUCIBLE ?= 1

CANISTER := oracle_registry
PACKAGE := oracle-registry-canister
WASM := target/wasm32-unknown-unknown/release/oracle_registry_canister.wasm
DID := crates/oracle-registry-canister/oracle-registry-canister.did
RELEASE_DIR := target/release-artifacts

.PHONY: help build wasm canister extract_did bake_candid_metadata node test lint e2e latency smoke \
	release publish network network-stop deploy governance check-identity

help: ## List the targets
	@grep -E '^[a-z0-9_-]+:.*## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*## "}; {printf "  %-22s %s\n", $$1, $$2}'

build: canister node ## The canister wasm and the node binary

wasm: ## The registry canister wasm alone, as the PocketIC tests install it
	cargo build --target wasm32-unknown-unknown --release --locked -p $(PACKAGE)

canister: wasm ## The registry canister wasm, with its .did extracted and baked in
	$(MAKE) --no-print-directory extract_did bake_candid_metadata

extract_did: ## Regenerate the .did from the built wasm
	candid-extractor $(WASM) > $(DID).tmp && mv $(DID).tmp $(DID) || { rm -f $(DID).tmp; exit 1; }

# Public, so tools such as `icp canister call` read the interface from the canister.
bake_candid_metadata: ## Embed the .did in the wasm as candid:service
	ic-wasm $(WASM) -o $(WASM) metadata candid:service -f $(DID) -v public --keep-name-section

node: ## The oracle-node binary for this machine
	cargo build --release --locked -p oracle-node --bin oracle-node

# The PocketIC tests install the wasm that ORACLE_CANISTER_WASM names, so a build
# error stops make before the tests. Without the variable, the tests build the wasm.
# The workspace build turns on `pure-rust` everywhere, so oracle-wire alone
# runs its vectors on `libsecp`, the backend the node ships with.
# ORACLE_PREVIOUS_WASM names the wasm of the previous release, for the upgrade and
# rollback test: the oracle_registry wasm of that GitHub release, checked against
# its SHA256SUMS. Nothing downloads it. Without it the test skips, and under CI it fails.
test: wasm ## Every test, PocketIC included, and the wire vectors on both backends
	ORACLE_CANISTER_WASM=$(CURDIR)/$(WASM) \
		$(if $(ORACLE_PREVIOUS_WASM),ORACLE_PREVIOUS_WASM=$(abspath $(ORACLE_PREVIOUS_WASM))) \
		cargo test --workspace --locked
	cargo test -p oracle-wire --locked

lint: ## Formatting, then clippy for the workspace and the canister's wasm32 build
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --locked -- -D warnings
	cargo clippy -p oracle-wire --all-targets --locked -- -D warnings
	cargo clippy --target wasm32-unknown-unknown -p $(PACKAGE) --locked -- -D warnings

e2e: wasm ## The whole system on PocketIC: canister, node binary, SDK client
	ORACLE_CANISTER_WASM=$(CURDIR)/$(WASM) cargo test -p oracle-node --locked --test e2e

latency: wasm ## Live latency from the venues to the SDK on this machine; LATENCY_SECS (default 60), LATENCY_FEED
	ORACLE_CANISTER_WASM=$(CURDIR)/$(WASM) cargo test --release -p oracle-node --locked --test latency -- --ignored --nocapture

smoke: ## The icp-cli path on a local network: deploy, and the calls init and rotate print
	scripts/smoke.sh

release: ## Reproducible wasm and Linux node binaries (amd64, arm64), with SHA256SUMS
	release/build.sh

publish: ## Upload the release artifacts and release/install.sh as GitHub release v<version>
	release/publish.sh

network: ## Start the local network in the background
	icp network start -d

network-stop: ## Stop the local network
	icp network stop

# Mainnet takes the reproducible release build unless REPRODUCIBLE=0; scripts/icp-wasm.sh
# enforces it.
deploy: check-identity ## Deploy the canister to ENV (local or ic); REPRODUCIBLE=0 skips Docker
ifeq ($(ENV),ic)
ifneq ($(REPRODUCIBLE),0)
	$(MAKE) --no-print-directory release
endif
	REPRODUCIBLE=$(REPRODUCIBLE) icp deploy $(CANISTER) -e ic --mode $(MODE) --identity $(IDENTITY)
else
	icp deploy $(CANISTER) -e $(ENV) --mode $(MODE) $(if $(IDENTITY),--identity $(IDENTITY),)
endif

governance: check-identity ## Print the canister id and governance address for ENV
	@echo "canister   $$(icp canister status $(CANISTER) -e $(ENV) --id-only)"
	@echo "governance $$(icp canister call $(CANISTER) refresh_governance_key '()' -e $(ENV) \
		$(if $(IDENTITY),--identity $(IDENTITY),) | grep -o '0x[0-9a-fA-F]\{40\}')"

# A mainnet canister's controller is the deploying identity. The anonymous
# identity is shared by everyone, so it must never be one.
check-identity:
ifeq ($(ENV),ic)
	@test -n "$(IDENTITY)" || { echo "ENV=ic needs IDENTITY=<icp identity>: it becomes the controller" >&2; exit 1; }
	@test "$(IDENTITY)" != anonymous || { echo "the anonymous identity must never control a mainnet canister" >&2; exit 1; }
endif
