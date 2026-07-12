# COPR SCM ("make srpm") entry point. COPR clones the repo at the requested
# committish and runs `make -f .copr/Makefile srpm outdir=... spec=...` in a
# network-enabled builder — so dependencies are vendored HERE, and the actual
# RPM build stays offline. The spec's Version must match the crate version
# (crates/machine-krb-service) — bump both together.

outdir ?= .
# NOT `spec ?=`: COPR passes spec=<checkout DIRECTORY> on the make command
# line, which would override any makefile default — so use our own name.
SPECFILE := packaging/machine-krb-service.spec

srpm:
	dnf -y install cargo git-core rpm-build xz
	set -e; \
	VERSION=$$(sed -n 's/^Version:[[:space:]]*//p' $(SPECFILE)); \
	TOP=$$(mktemp -d); mkdir -p $$TOP/SOURCES; \
	git archive --prefix=machine-krb-service-$$VERSION/ \
	    -o $$TOP/SOURCES/machine-krb-service-$$VERSION.tar.gz HEAD; \
	cargo vendor --locked vendor >/dev/null; \
	tar -cJf $$TOP/SOURCES/machine-krb-service-$$VERSION-vendor.tar.xz vendor; \
	rpmbuild -bs --define "_topdir $$TOP" --define "_srcrpmdir $(outdir)" $(SPECFILE)
