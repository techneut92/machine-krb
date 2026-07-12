# machine-krb-service — build & deploy.
# Run as your normal user (`make install`); sudo is used only where needed,
# so cargo never runs as root. Idempotent — re-run to upgrade.
#
# The default 'machine-krb' group is created here and you're added to it. The
# group that actually guards the cache is read from config.yaml at runtime, so
# to use a different (existing) group just set `group:` there — no unit edit.

PREFIX      ?= /usr/local
BINDIR      := $(PREFIX)/bin
UNITDIR     ?= /etc/systemd/system
DISPATCHDIR ?= /etc/NetworkManager/dispatcher.d
SYSCONFDIR  ?= /etc
CONFDIR     := $(SYSCONFDIR)/machine-krb
TARGETDIR   := target
BIN         := $(TARGETDIR)/release/machine-krb-service

MUSL_TARGET := x86_64-unknown-linux-musl
VERSION     := $(shell sed -n 's/^version = "\(.*\)"/\1/p' crates/machine-krb-service/Cargo.toml | head -1)

.PHONY: all build test check install uninstall packages bump

all: build

build:
	# --locked: the committed (reviewed) Cargo.lock is authoritative for the
	# binary that ends up running as root — never silently re-resolve deps.
	cargo build --release --locked --target-dir $(TARGETDIR)

test:
	cargo test --workspace --all-features --locked

check: test
	cargo clippy --workspace --all-features --all-targets --locked -- -D warnings
	cargo fmt --check

# Build .rpm, .deb and .apk into dist/ from one fully-static musl binary
# (works on glibc and musl distros alike — the crate links no C libraries).
# Requires: rustup target add $(MUSL_TARGET); nfpm (https://nfpm.goreleaser.com).
packages:
	command -v nfpm >/dev/null || { echo "nfpm not found — install it (e.g. brew install nfpm)" >&2; exit 1; }
	rustup target list --installed | grep -q $(MUSL_TARGET) || rustup target add $(MUSL_TARGET)
	cargo build --release --locked --target $(MUSL_TARGET)
	# packaged unit points at /usr/bin (distro layout), not /usr/local/bin
	mkdir -p target/pkg dist
	sed 's|ExecStart=/usr/local/bin/|ExecStart=/usr/bin/|' systemd/machine-krb-service.service > target/pkg/machine-krb-service.service
	VERSION=$(VERSION) nfpm package -f packaging/nfpm.yaml -p rpm -t dist/
	VERSION=$(VERSION) nfpm package -f packaging/nfpm.yaml -p deb -t dist/
	VERSION=$(VERSION) nfpm package -f packaging/nfpm.yaml -p apk -t dist/
	@echo
	@ls -lh dist/

# Sync every version spot for a SERVICE release: crate Cargo.toml, Cargo.lock,
# rpm spec (Version + %changelog) and debian/changelog. Review the diff, commit,
# tag service-vX.Y.Z and push — CI publishes everywhere (see README, Releasing).
# The library crate versions independently and is NOT touched here: for a lib
# release edit crates/machine-krb/Cargo.toml and tag lib-vX.Y.Z.
# NOTE must not contain '/' or '&' (it travels through sed).
#   make bump VERSION=0.1.2 NOTE="what changed"
NOTE ?= New release.

bump:
	@echo "$(VERSION)" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$$' \
		|| { echo "usage: make bump VERSION=x.y.z [NOTE=\"what changed\"]" >&2; exit 1; }
	@set -e; \
	cur=$$(sed -n 's/^version = "\(.*\)"/\1/p' crates/machine-krb-service/Cargo.toml | head -1); \
	[ "$$cur" != "$(VERSION)" ] || { echo "already at $(VERSION)" >&2; exit 1; }; \
	who="$$(git config user.name) <$$(git config user.email)>"; \
	sed -i "0,/^version = \"$$cur\"/s//version = \"$(VERSION)\"/" crates/machine-krb-service/Cargo.toml; \
	cargo metadata --offline --format-version 1 >/dev/null; \
	sed -i "s/^\(Version:[[:space:]]*\)$$cur$$/\1$(VERSION)/" packaging/machine-krb-service.spec; \
	sed -i "/^%changelog/a * $$(LC_ALL=C date '+%a %b %d %Y') $$who - $(VERSION)-1\n- $(NOTE)\n" packaging/machine-krb-service.spec; \
	{ printf 'machine-krb-service (%s-1) unstable; urgency=medium\n\n  * %s\n\n -- %s  %s\n\n' \
		"$(VERSION)" "$(NOTE)" "$$who" "$$(date -R)"; cat debian/changelog; } > debian/changelog.new; \
	mv debian/changelog.new debian/changelog
	@git --no-pager diff --stat
	@echo
	@echo "next: review the diff, commit, then:"
	@echo "  git tag service-v$(VERSION) && git push origin main service-v$(VERSION)"

install: build
	sudo groupadd -rf machine-krb
	# id -un (not $$USER): immune to a spoofed environment; '--' ends options.
	sudo usermod -aG machine-krb -- "$$(id -un)"
	sudo install -D -m 0755 $(BIN) $(BINDIR)/machine-krb-service
	# ostree/SELinux: /usr/local/bin is bin_t by default; restore in case the
	# binary was ever mv'ed here from $$HOME (user_home_t breaks ExecStart).
	command -v restorecon >/dev/null && sudo restorecon -F $(BINDIR)/machine-krb-service || true
	# Point ExecStart at $(BINDIR) in case PREFIX was overridden.
	sed 's|ExecStart=/usr/local/bin/|ExecStart=$(BINDIR)/|' systemd/machine-krb-service.service > $(TARGETDIR)/machine-krb-service.service
	sudo install -D -m 0644 $(TARGETDIR)/machine-krb-service.service $(UNITDIR)/machine-krb-service.service
	sudo install -D -m 0644 systemd/machine-krb-service.timer $(UNITDIR)/machine-krb-service.timer
	# Refresh on network/VPN up too, not just hourly (skipped if NM is absent).
	if [ -d $(DISPATCHDIR) ]; then sudo install -m 0755 systemd/90-machine-krb-service $(DISPATCHDIR)/90-machine-krb-service; fi
	# Default config — never clobber an existing one (preserves your edits on upgrade).
	if [ -f $(CONFDIR)/config.yaml ]; then echo "keeping existing $(CONFDIR)/config.yaml"; \
		else sudo install -D -m 0644 config/config.yaml $(CONFDIR)/config.yaml; fi
	# Boot-time creation of /run/machine-krb (see the comment in the conf file
	# for why tmpfiles.d and not RuntimeDirectory=); apply immediately too.
	sudo install -D -m 0644 systemd/machine-krb.tmpfiles.conf /etc/tmpfiles.d/machine-krb.conf
	sudo systemd-tmpfiles --create machine-krb.conf || true
	sudo systemctl daemon-reload
	sudo systemctl enable --now machine-krb-service.timer
	# First refresh needs the KDC — fine if that fails right now (off VPN);
	# the timer and the network dispatcher retry.
	sudo systemctl start machine-krb-service.service \
		|| echo "!! first refresh failed (KDC unreachable — off VPN?); it will retry automatically" >&2
	@echo
	systemctl list-timers machine-krb-service.timer --no-pager || true
	@echo
	# sudo: your own 'machine-krb' group membership only applies after re-login.
	sudo $(BINDIR)/machine-krb-service status || true
	@echo
	@echo "Installed. Note: your 'machine-krb' group membership applies after you log in again."

uninstall:
	sudo systemctl disable --now machine-krb-service.timer 2>/dev/null || true
	sudo systemctl stop machine-krb-service.service 2>/dev/null || true
	sudo rm -f $(UNITDIR)/machine-krb-service.service $(UNITDIR)/machine-krb-service.timer \
		$(DISPATCHDIR)/90-machine-krb-service $(BINDIR)/machine-krb-service \
		/etc/tmpfiles.d/machine-krb.conf
	sudo systemctl daemon-reload
	@echo "Removed the binary + units. Left in place: $(CONFDIR)/config.yaml, the"
	@echo "'machine-krb' group, and /run/machine-krb (rm/groupdel them manually if unwanted)."
