SHELL := /bin/bash
spec ?= sshcast-client.spec
outdir ?= .

SPEC_ABS := $(abspath $(spec))
OUTDIR_ABS := $(abspath $(outdir))
REPO_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)

.PHONY: srpm

srpm:
	@set -euo pipefail; \
	if ! command -v cargo >/dev/null 2>&1 || ! command -v git >/dev/null 2>&1 || ! command -v rpmbuild >/dev/null 2>&1; then \
		dnf -y install cargo git-core rpm-build; \
	fi; \
	ROOT="$(REPO_ROOT)"; \
	SPEC="$(SPEC_ABS)"; \
	if [ -z "$$SPEC" ] || [ -d "$$SPEC" ]; then \
		SPEC="$$ROOT/sshcast-client.spec"; \
	fi; \
	OUTDIR="$(OUTDIR_ABS)"; \
	NAME=$$(awk -F: '/^Name:[[:space:]]*/ {gsub(/^[[:space:]]+|[[:space:]]+$$|\r/, "", $$2); print $$2; exit}' "$$SPEC"); \
	VERSION=$$(awk -F: '/^Version:[[:space:]]*/ {gsub(/^[[:space:]]+|[[:space:]]+$$|\r/, "", $$2); print $$2; exit}' "$$SPEC"); \
	if [ -z "$$NAME" ] || [ -z "$$VERSION" ]; then \
		echo "Failed to parse Name/Version from $$SPEC" >&2; \
		exit 1; \
	fi; \
	if [ ! -f "$$ROOT/sshcast-proto/Cargo.toml" ]; then \
		git -C "$$ROOT" submodule update --init --recursive; \
	fi; \
	mkdir -p "$$OUTDIR"; \
	STAGE_ROOT=$$(mktemp -d); \
	trap 'rm -rf "$$STAGE_ROOT"' EXIT; \
	PKG_DIR="$$STAGE_ROOT/$$NAME-$$VERSION"; \
	mkdir -p "$$PKG_DIR" "$$STAGE_ROOT/SOURCES" "$$STAGE_ROOT/SPECS" "$$STAGE_ROOT/BUILD" "$$STAGE_ROOT/RPMS" "$$STAGE_ROOT/SRPMS"; \
	tar --exclude='.git' --exclude='./target' --exclude='sshcast-proto/target' --exclude='./vendor' --exclude='./.cargo' --exclude='*.rpm' --exclude='*.src.rpm' -cf - -C "$$ROOT" . | tar -C "$$PKG_DIR" -xf -; \
	(cd "$$PKG_DIR" && \
		cargo vendor --locked vendor >/dev/null && \
		mkdir -p .cargo && \
		printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "vendor"\n' > .cargo/config.toml); \
	tar -C "$$STAGE_ROOT" --exclude='.git' --exclude="$$NAME-$$VERSION/target" --exclude="$$NAME-$$VERSION/sshcast-proto/target" -czf "$$STAGE_ROOT/SOURCES/$$NAME-$$VERSION.tar.gz" "$$NAME-$$VERSION"; \
	cp "$$SPEC" "$$STAGE_ROOT/SPECS/$$NAME.spec"; \
	rpmbuild -bs \
		--define "_topdir $$STAGE_ROOT" \
		--define "_sourcedir $$STAGE_ROOT/SOURCES" \
		--define "_srcrpmdir $$OUTDIR" \
		"$$STAGE_ROOT/SPECS/$$NAME.spec"
