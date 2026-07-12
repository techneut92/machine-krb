#!/bin/sh
# Build the Debian source-package artifacts (.dsc, .orig.tar.gz,
# .orig-vendor.tar.gz, .debian.tar.xz) that the OBS package consumes.
# Run from the repo root; used by the release workflow and by hand:
#   packaging/make-obs-debsrc.sh <outdir>
# Needs: git, cargo (>= lockfile v4, i.e. 1.78+), dpkg-source, python3.
set -eu

outdir=${1:?usage: make-obs-debsrc.sh <outdir>}
mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)

# upstream version = debian/changelog version minus the Debian revision
version=$(dpkg-parsechangelog -SVersion | sed 's/-[0-9][^-]*$//')

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

git archive --prefix="machine-krb-service-$version/" \
    -o "$work/machine-krb-service_$version.orig.tar.gz" HEAD
tar -xzf "$work/machine-krb-service_$version.orig.tar.gz" -C "$work"

cd "$work/machine-krb-service-$version"
cargo vendor --locked vendor >/dev/null 2>&1

# dpkg-source -x silently drops files matching its default ignore patterns
# (*.orig) on extraction, which would break cargo's checksum verification —
# scrub Cargo.toml.orig from every vendored crate and its checksum manifest.
python3 - <<'EOF'
import json, os, glob
for crate in glob.glob('vendor/*/'):
    orig = os.path.join(crate, 'Cargo.toml.orig')
    if os.path.exists(orig):
        os.remove(orig)
        ck = os.path.join(crate, '.cargo-checksum.json')
        d = json.load(open(ck))
        d['files'].pop('Cargo.toml.orig', None)
        json.dump(d, open(ck, 'w'))
EOF

tar -czf "../machine-krb-service_$version.orig-vendor.tar.gz" vendor
cd "$work"
dpkg-source -b "machine-krb-service-$version"

mv machine-krb-service_"$version"* "$outdir"/
ls -l "$outdir"
