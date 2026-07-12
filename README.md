# machine-krb

[![CI](https://github.com/techneut92/machine-krb/actions/workflows/ci.yml/badge.svg)](https://github.com/techneut92/machine-krb/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/machine-krb?logo=rust&color=brightgreen)](https://crates.io/crates/machine-krb)
[![docs.rs](https://img.shields.io/docsrs/machine-krb?logo=docs.rs)](https://docs.rs/machine-krb)
[![MSRV](https://img.shields.io/crates/msrv/machine-krb?label=msrv)](crates/machine-krb/Cargo.toml)
[![Release](https://img.shields.io/github/v/release/techneut92/machine-krb?label=release&color=brightgreen)](https://github.com/techneut92/machine-krb/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/techneut92/machine-krb/total?label=downloads&color=blue)](https://github.com/techneut92/machine-krb/releases)
[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-support-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/techneut92)

Keep an **Active Directory machine-account Kerberos ticket** fresh on a Linux
host, and verify the host is *properly* joined — using the system MIT krb5
tools, no reimplemented Kerberos.

Some KDC policies require **compound authentication** (FAST armoring): the KDC
only issues a service ticket when the request is armored with the requesting
*device's* machine ticket. That machine ticket comes from the host keytab
(`/etc/krb5.keytab`), lives only a few hours, and normally needs root to
refresh — so the moment a client (an RDP session, a GSSAPI LDAP bind, any
service that armors) reaches for it, you hit a sudo prompt and, right after a
fresh mint, a KDC "settle" race. This project keeps the ticket permanently
warm so consumers just use it.

## Two crates

| crate | kind | what |
|-------|------|------|
| [`machine-krb`](crates/machine-krb) | **library** | machine-identity discovery from the keytab, ticket renew/mint/ensure, layered AD-join verification. Reusable — depend on it from anything. |
| [`machine-krb-service`](crates/machine-krb-service) | **binary / service** | a root systemd oneshot (hourly + boot + on VPN-up) that uses the library to keep `/run/machine-krb/armor.ccache` valid for every consumer. |

The split is deliberate: the library carries the Kerberos/AD logic and is
useful on its own (build your own agent, a GUI, a health check); the service is
one opinionated deployment of it.

```
machine-krb-service.timer ──hourly / boot / VPN-up──▶ machine-krb-service run   (root)
                                                       │  kinit -R  (renew, cheap)
                                                       │  kinit -k  (mint from keytab if needed)
                                                       ▼
                                     /run/machine-krb/armor.ccache   (root:machine-krb 0640)
                                                       ▲
                        any consumer that FAST-armors (RDP client, GSSAPI bind, …) reads it
```

## Quick start (the service)

From source on a dev box:

```bash
make install                                 # build, install units, enable the timer
machine-krb-service status                    # is the machine ticket valid?
sudo machine-krb-service check-join --deep    # prove the join against the KDC
```

On Fedora / RHEL (and friends) the easiest path is the
[COPR repo](https://copr.fedorainfracloud.org/coprs/techneut92/machine-krb/) —
Fedora 43+/rawhide, EPEL 9/10, x86_64 + aarch64, updates land with `dnf upgrade`:

```bash
sudo dnf copr enable techneut92/machine-krb
sudo dnf install machine-krb-service
sudo systemctl enable --now machine-krb-service.timer
```

(EL needs `dnf-plugins-core` for `dnf copr`; on Fedora Atomic add the
[repo file](https://copr.fedorainfracloud.org/coprs/techneut92/machine-krb/)
to `/etc/yum.repos.d/` and `rpm-ostree install machine-krb-service` — the COPR
page has copy-paste instructions.)

Or from packages — `make packages` (or the GitHub release assets) produces
**.rpm, .deb and .apk from one fully-static musl binary**:

```bash
sudo dnf install ./machine-krb-service-*.rpm        # Fedora/RHEL
sudo rpm-ostree install ./machine-krb-service-*.rpm # Fedora Atomic (Silverblue/Kinoite/Bazzite) — then reboot
sudo apt install ./machine-krb-service_*.deb        # Debian/Ubuntu
apk add --allow-untrusted machine-krb-service_*.apk # Alpine
sudo systemctl enable --now machine-krb-service.timer     # (systemd distros)
```

Then tune `/etc/machine-krb/config.yaml` to taste — the group that may read
the ticket, the realm on multi-realm hosts, retry/escalation behavior. Changes
apply on the next run (`sudo systemctl restart machine-krb-service`); upgrades
never overwrite the file. All keys are documented in the
[service README](crates/machine-krb-service/README.md#configuration).

Full details in the crate READMEs:
- **Library API** → [`crates/machine-krb/README.md`](crates/machine-krb/README.md)
- **Service** (systemd model, configuration, security, troubleshooting) →
  [`crates/machine-krb-service/README.md`](crates/machine-krb-service/README.md)

## Requirements

- An AD-joined Linux host (realmd/SSSD or equivalent) with `/etc/krb5.keytab`.
- System MIT krb5 client tools (`/usr/bin/kinit`, `klist`, `kdestroy`) — the
  binary itself is static (musl-friendly, no glibc/libkrb5 linkage), but these
  tools must exist on the host.
- Rust ≥ 1.85 to build (floor set by `clap`; the library itself is lower).

## Support

If this project saves you some time, you can support its development:

- **Ko-fi** — [ko-fi.com/techneut92](https://ko-fi.com/techneut92) (one-off tips, no account needed)
- **Revolut** — [revolut.me/techneut92](https://revolut.me/techneut92)
- **Ethereum (ETH)** — `0x15d9B8383A7cbe9f99F72aC29106C53bbcf4ea40` (Ethereum network; ETH / ERC-20 only)

[![ko-fi](https://img.shields.io/badge/Support%20me%20on-Ko--fi-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/techneut92)
[![Revolut](https://img.shields.io/badge/Revolut-tip-0666EB?logo=revolut&logoColor=white)](https://revolut.me/techneut92)

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option.
