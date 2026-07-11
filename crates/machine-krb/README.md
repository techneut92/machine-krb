# machine-krb

Manage an **Active Directory machine-account Kerberos ticket** and verify the
**AD join** on a Linux host — a small, dependency-light library over the system
MIT krb5 tools.

It does two things:

1. **Keep a machine-account ticket valid.** Discover the machine principal from
   the keytab, then renew (`kinit -R`, cheap) or mint (`kinit -k`) a TGT into a
   `FILE:` credential cache, and hand that cache to a group so other processes
   can use it.
2. **Answer "is this host properly joined?"** — a layered check that ends in
   actually authenticating the machine credential against the KDC (the
   equivalent of `adcli testjoin`).

The motivating use case is **compound authentication / FAST armoring**: some
KDC policies only issue a service ticket when the request is armored with the
device's machine ticket. A consumer (an RDP client, a GSSAPI LDAP bind, …) then
needs that machine ticket to exist in a cache and stay valid. This crate is the
engine behind the [`machine-krb-service`](../machine-krb-service) service, but is
useful on its own for agents, GUIs, or health checks.

## Design

It **shells out to the system MIT krb5 tools** (`kinit`, `klist`, …) rather than
linking libkrb5 or reimplementing Kerberos — the system tools already handle
PKINIT, FAST and the distribution's crypto policy correctly. Tool paths are
**absolute by default** (`/usr/bin/kinit`, …) so a `kinit` from Homebrew or a
custom `PATH` can't silently shadow the system one; override them via [`Tools`]
for non-standard layouts.

No async, no unsafe. Hard dependencies are `thiserror` and `libc` (a single
`O_NOFOLLOW` constant for race-free file-permission handling); `serde` is
opt-in. Spawned tools get a scrubbed Kerberos environment (`KRB5_CONFIG`,
`KRB5CCNAME`, `KRB5_KTNAME`, … removed), so a hostile caller environment can't
redirect them.

## Example

```rust,no_run
use std::path::Path;
use machine_krb::{ArmorCache, Freshness, MachineIdentity, Tools};

let tools = Tools::default();

// Who is this machine? (reads the principal out of the keytab — needs root)
let id = MachineIdentity::discover(&tools, "/etc/krb5.keytab")?;

// A group-readable directory + cache for the ticket.
let gid = machine_krb::lookup_gid(&tools, "machine-krb")?;
machine_krb::prepare_dir(Path::new("/run/machine-krb"), Some(gid))?; // root:grp 0750
let cache = ArmorCache::new("/run/machine-krb/armor.ccache");

// Make sure it holds a valid ticket: renew if possible, else mint from keytab.
match cache.ensure(&tools, &id)? {
    Freshness::Renewed => println!("renewed {}", id.principal),
    Freshness::Minted => println!("minted {} (fresh — may need seconds to settle)", id.principal),
}
cache.set_access(gid)?; // root:machine-krb 0640, group members can now use it
# Ok::<(), machine_krb::Error>(())
```

Verifying the join:

```rust,no_run
use std::path::Path;
use machine_krb::{check_join, Tools};

// realm = None → use the first machine principal; deep = true → prove it.
let status = check_join(&Tools::default(), Path::new("/etc/krb5.keytab"), None, true);
if status.is_properly_joined() {
    println!("joined and the machine credential authenticates against the KDC");
} else if status.is_configured() {
    println!("configured, but the credential could not be proven: {:?}", status.credential_error);
}
```

## API at a glance

| item | purpose |
|------|---------|
| [`Tools`] | absolute paths to `kinit`/`klist`/`realm`/… — `Default`, or override |
| [`MachineIdentity::discover`] | read `NAME$@REALM` from the keytab |
| [`ArmorCache`] | a `FILE:` ticket cache: `ensure` / `renew` / `mint` / `is_valid` / `set_access` / `klist_text` / `destroy` |
| [`Freshness`] | how `ensure` succeeded: `Renewed` or `Minted` |
| [`prepare_dir`] / [`lookup_gid`] | create the group-owned cache directory / resolve a group to its gid |
| [`check_join`] / [`JoinStatus`] | layered join report; `verify_credential` for the deep check alone |
| [`Error`] / [`Result`] | error type (all variants carry the offending path/program) |

### The join layers

`check_join` fills a [`JoinStatus`] with, weakest to strongest:

1. **configured** — `realm list` is non-empty. Local state only; a machine
   deleted in AD still reports this.
2. **credential present** — the keytab holds a `NAME$@REALM` principal (root).
3. **credential proven** (`deep`, root) — `kinit -k` into a private throwaway
   cache authenticates against the KDC. Strongest client-side check there is:
   it also proves the computer object exists and is enabled (disabled →
   *credentials revoked*, deleted → *not found*).

Plus an **advisory** `sssd_status` (from `sssctl domain-status`, root) —
orthogonal: "offline" usually just means the network is down.

## Permissions

Practically everything needs **root**, because the machine keytab
(`/etc/krb5.keytab`) is root-only and even renewing rewrites the cache file.
Reading an existing cache ([`ArmorCache::is_valid`], [`ArmorCache::klist_text`])
and the shallow (non-`deep`) join check work unprivileged.

**Security:** whoever can read the cache holds the machine account's TGT and can
authenticate to AD *as the computer*. Keep the cache and its group restricted.

## Features

- `serde` (off by default) — derives `Serialize` on [`JoinStatus`],
  [`MachineIdentity`] and [`Freshness`] for JSON output.

## Minimum supported Rust

Rust **1.85** (edition 2024) — the floor is set by `clap`; the library's own
code builds lower. Tested on 1.85 and current stable.

## License

Dual-licensed under [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE),
at your option.

[`Tools`]: https://docs.rs/machine-krb/latest/machine_krb/struct.Tools.html
[`MachineIdentity::discover`]: https://docs.rs/machine-krb/latest/machine_krb/struct.MachineIdentity.html
[`ArmorCache`]: https://docs.rs/machine-krb/latest/machine_krb/struct.ArmorCache.html
[`ArmorCache::is_valid`]: https://docs.rs/machine-krb/latest/machine_krb/struct.ArmorCache.html
[`ArmorCache::klist_text`]: https://docs.rs/machine-krb/latest/machine_krb/struct.ArmorCache.html
[`Freshness`]: https://docs.rs/machine-krb/latest/machine_krb/enum.Freshness.html
[`prepare_dir`]: https://docs.rs/machine-krb/latest/machine_krb/fn.prepare_dir.html
[`lookup_gid`]: https://docs.rs/machine-krb/latest/machine_krb/fn.lookup_gid.html
[`check_join`]: https://docs.rs/machine-krb/latest/machine_krb/fn.check_join.html
[`JoinStatus`]: https://docs.rs/machine-krb/latest/machine_krb/struct.JoinStatus.html
[`Error`]: https://docs.rs/machine-krb/latest/machine_krb/enum.Error.html
[`Result`]: https://docs.rs/machine-krb/latest/machine_krb/type.Result.html
