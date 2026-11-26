spec ?= sshcast-client.spec
outdir ?= .

.PHONY: srpm

srpm:
	@set -eu; \
	if ! command -v cargo >/dev/null 2>&1 || ! command -v git >/dev/null 2>&1 || ! command -v rpmbuild >/dev/null 2>&1; then \
		dnf -y install cargo git-core rpm-build; \
	fi; \
	if [ ! -f sshcast-proto/Cargo.toml ]; then \
		git submodule update --init --recursive; \
	fi; \
	NAME=$$(awk -F: '/^Name:[[:space:]]*/ {gsub(/^[[:space:]]+|[[:space:]]+$$|\r/, "", $$2); print $$2; exit}' "$(spec)"); \
	VERSION=$$(awk -F: '/^Version:[[:space:]]*/ {gsub(/^[[:space:]]+|[[:space:]]+$$|\r/, "", $$2); print $$2; exit}' "$(spec)"); \
	if [ -z "$$NAME" ] || [ -z "$$VERSION" ]; then \
		echo "Failed to parse Name/Version from $(spec)" >&2; \
		exit 1; \
	fi; \
	mkdir -p "$(outdir)"; \
	OUT_DIR=$$(cd "$(outdir)" && pwd); \
	STAGE_ROOT=$$(mktemp -d); \
	trap 'rm -rf "$$STAGE_ROOT"' EXIT; \
	PKG_DIR="$$STAGE_ROOT/$$NAME-$$VERSION"; \
	mkdir -p "$$PKG_DIR" "$$STAGE_ROOT/SOURCES" "$$STAGE_ROOT/SPECS" "$$STAGE_ROOT/BUILD" "$$STAGE_ROOT/RPMS" "$$STAGE_ROOT/SRPMS"; \
	tar --exclude='.git' --exclude='./target' --exclude='./vendor' --exclude='./.cargo' --exclude='*.rpm' --exclude='*.src.rpm' -cf - . | tar -C "$$PKG_DIR" -xf -; \
	(cd "$$PKG_DIR" && \
		cargo vendor --locked vendor >/dev/null && \
		mkdir -p .cargo && \
		printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "vendor"\n' > .cargo/config.toml); \
	tar -C "$$STAGE_ROOT" -czf "$$STAGE_ROOT/SOURCES/$$NAME-$$VERSION.tar.gz" "$$NAME-$$VERSION"; \
	cp "$(spec)" "$$STAGE_ROOT/SPECS/$$NAME.spec"; \
	rpmbuild -bs \
		--define "_topdir $$STAGE_ROOT" \
		--define "_sourcedir $$STAGE_ROOT/SOURCES" \
		--define "_srcrpmdir $$OUT_DIR" \
		"$$STAGE_ROOT/SPECS/$$NAME.spec"
