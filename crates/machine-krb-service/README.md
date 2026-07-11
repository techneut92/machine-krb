# machine-krb-service

A small **systemd service that keeps a Linux host's Active Directory
machine-account Kerberos ticket fresh**, so anything that needs it — FAST
armoring / compound authentication for an RDP client, a GSSAPI LDAP bind, etc.
— always finds a valid ticket in `/run/machine-krb/armor.ccache`.

It's a thin wrapper around the [`machine-krb`](../machine-krb) library: a root
oneshot that renews the machine ticket (or mints a new one from the keytab)
each time it runs, driven by a timer.

## Why a service

The machine ticket comes from `/etc/krb5.keytab` (root-only) and lives only a
few hours. Without a service, every consumer that needs it triggers a `sudo`
`kinit` — and a *freshly minted* machine ticket takes a few seconds to settle
before the KDC will honor it for compound auth, so the first attempt right
after a mint can fail. Refreshing continuously in the background as root means
consumers only ever see a warm, already-settled ticket. No sudo prompt at use
time, no settle race.

## Install

**From packages** (rpm/deb/apk — all built from one static musl binary, see
`make packages`): install the package, then
`systemctl enable --now machine-krb-service.timer` and add your user to the
`machine-krb` group. On Alpine (no systemd) the hourly refresh runs via
busybox crond (`/etc/periodic/hourly`) instead, and `check-join` degrades to
the keytab + credential layers (no realmd there).

**From source on a dev box:**

```bash
make install
```

Builds the release binary, then (using `sudo` only where required — `cargo`
never runs as root):

- installs the binary to `/usr/local/bin/machine-krb-service`
- installs `machine-krb-service.service` + `.timer` to `/etc/systemd/system`
- installs a NetworkManager dispatcher hook (if NetworkManager is present)
- installs the default config to `/etc/machine-krb/config.yaml` (never
  overwriting an existing one — your edits survive upgrades)
- creates the `machine-krb` system group and adds you to it
- enables the timer and runs the first refresh

Your **`machine-krb` group membership only takes effect after you log in
again** — until then use `sudo machine-krb-service status` to read the cache.

Overridable make variables: `PREFIX` (default `/usr/local`), `UNITDIR`
(`/etc/systemd/system`), `DISPATCHDIR` (`/etc/NetworkManager/dispatcher.d`),
`SYSCONFDIR` (`/etc`). The unit's `ExecStart` is rewritten to match `PREFIX` at
install time.

Other targets: `make build`, `make test`, `make check` (tests + clippy
`-D warnings`), `make uninstall`.

## Commands

```bash
machine-krb-service status                    # is the machine ticket valid? (--json for tooling)
machine-krb-service check-join                # is this host AD-joined? (config level, no root)
sudo machine-krb-service check-join --deep    # PROVE the credential against the KDC (root)
sudo machine-krb-service run                  # what the timer runs: renew, or mint if needed
```

Global flags (override the config file): `--config <path>`, `--keytab <path>`,
`--ccache <path>`, `--group <name>`, `--realm <REALM>`. `run` also takes
`--no-chown` (leave the cache root-only).

Exit codes are meaningful, for monitoring and for systemd:

| code | meaning |
|------|---------|
| `0` | success |
| `1` | `status`: cache invalid · `check-join`: not joined / not proven |
| `75` | `run`: **transient** failure (off VPN / KDC unreachable) — the timer retries; the unit is *not* marked failed (`SuccessExitStatus=75`) |
| `78` | `run`: **permanent** failure (not joined, credential revoked, bad config) — needs an operator. Also issued after `escalate_after` *consecutive* transient runs, so an outage can't stay invisible behind exit 75 forever |

Failure lines on stderr carry sd-daemon `<3>`/`<4>` priority prefixes (when not
on a TTY), so journal-based monitoring can alert on priority even while the
unit is green.

## Configuration

Settings resolve as **built-in defaults → `/etc/machine-krb/config.yaml` →
CLI flags** (flags win). The file is optional; a missing file just means
defaults. Every key is optional:

```yaml
keytab: /etc/krb5.keytab
ccache: /run/machine-krb/armor.ccache

# Group whose members may read the machine ticket (root:<group> 0640).
# Point this at an existing restricted group if you have one — see Security.
group: machine-krb

# On a host joined to more than one realm, pick which machine principal to keep
# a ticket for (case-insensitive). Omit to use the first one in the keytab.
# realm: EXAMPLE.COM

# Per-run retry for transient (KDC-unreachable) failures; long-term retry is
# the timer's job regardless. escalate_after: after this many CONSECUTIVE
# transient runs, report permanent (failed unit) so an outage becomes visible;
# 0 disables. Values are clamped (attempts <= 10, backoff <= 60s) to stay
# under the unit's TimeoutStartSec.
retry:
  attempts: 3
  backoff_seconds: 10
  escalate_after: 12
```

Changing `group:` and restarting the service (`systemctl restart
machine-krb-service`) re-`chown`s the cache directory + file to the new group
on the next run — no unit edit needed.

## How it stays fresh

```
machine-krb-service.timer
   ├─ OnBootSec=2min          first refresh shortly after boot
   ├─ OnCalendar=hourly       then every hour (Persistent=true replays a missed run)
   └─ NetworkManager hook     also on connection / VPN up (90-machine-krb-service)
                    │
                    ▼
machine-krb-service.service  (Type=oneshot, root)
   renew (kinit -R) → or mint (kinit -k from keytab) → verify (klist -s)
   [every spawned tool capped at 30s — a kinit hung on a half-up VPN is
    killed and treated as a transient failure, not a wedged unit]
   [transient failure? retry a few times with backoff, within the run]
   writes /run/machine-krb/armor.ccache as root:<group> 0640
```

- `/run` is tmpfs, so the cache lives **only in memory** and is re-created after
  every boot — nothing sensitive is persisted to disk.
- `/run/machine-krb` is created at boot via **tmpfiles.d** (not
  `RuntimeDirectory=`, which would reset its ownership to root:root on every
  activation and fight the config-driven group);
  `TimeoutStartSec=3min` ensures a wedged run can't block the timer.
- The unit is heavily sandboxed (`ProtectSystem=strict`, `PrivateTmp`,
  `NoNewPrivileges`, `SystemCallFilter=@system-service`, an almost-empty
  capability set — just `CAP_CHOWN`, and `RestrictAddressFamilies` kept wide
  enough for the resolver).

## Files installed

| path | what |
|------|------|
| `/usr/local/bin/machine-krb-service` | the binary |
| `/etc/systemd/system/machine-krb-service.service` | the oneshot |
| `/etc/systemd/system/machine-krb-service.timer` | the schedule |
| `/etc/NetworkManager/dispatcher.d/90-machine-krb-service` | refresh on VPN/connection up |
| `/etc/tmpfiles.d/machine-krb.conf` | boot-time creation of `/run/machine-krb` |
| `/etc/machine-krb/config.yaml` | configuration (not overwritten on upgrade) |
| `/run/machine-krb/armor.ccache` | the ticket cache (created at runtime, tmpfs) |
| group `machine-krb` | default group allowed to read the cache |

## Security

Membership of the cache's group is **equivalent to holding the machine
account's Kerberos TGT** — a member can read the cache and authenticate to AD
*as this computer*. Only add accounts you'd trust with the machine credential
itself. (For the compound-auth use case that's the whole point: the consuming
process must be able to read the ticket to armor with it.)

You may set `group:` to an **existing restricted group** your org already
manages (e.g. one scoped to your admin account) instead of the default
`machine-krb` — just don't point it at a broad group like `users` or
`wheel`, which would let any member impersonate the computer.

## Behavior notes

- **Renew vs mint.** `kinit -R` (cheap, no keytab) only works while the current
  ticket is unexpired; the ~7-day renewable window is reached by repeated
  pre-expiry renewals, not as a grace period. After a long poweroff the ticket
  is expired and is re-minted from the keytab automatically.
- **Off-network / retry.** A refresh needs the KDC, so runs fail while off the
  network (or off the VPN). That's harmless: within a run it retries a few times
  (the `retry:` config) for a brief blip, and it exits `75` (treated as *not*
  failed) so the hourly timer and the NetworkManager VPN-up hook keep trying.
  Consumers must tolerate the cache being briefly absent after boot / while
  offline. A *permanent* problem (not joined, revoked) exits `78` and the unit
  shows `failed` — that's your cue to look. And after `escalate_after`
  consecutive transient runs (default 12 ≈ half a day) the service escalates to
  `78` too, so even an unrecognized failure mode eventually turns the unit red
  instead of staying green forever.
- **Machine-password rotation.** SSSD rotates the AD machine password (default
  ~30 days) and rewrites the keytab itself; this doesn't invalidate issued
  tickets, so the service is unaffected.

## Troubleshooting

```bash
systemctl status machine-krb-service.service      # last run result
journalctl -u machine-krb-service.service         # full history
systemctl list-timers machine-krb-service.timer   # next scheduled run
sudo machine-krb-service check-join --deep        # is the join itself the problem?
```

A `check-join --deep` failure of *credentials revoked* / *not found* means the
computer object in AD is disabled or deleted — re-join (`realm join` / `adcli`),
not a service problem.

## Uninstall

```bash
make uninstall     # stops/disables units, removes binary + units + hook
```

`/etc/machine-krb/config.yaml`, the `machine-krb` group, and `/run/machine-krb`
are left in place (remove them by hand — `sudo groupdel machine-krb`,
`sudo rm -r /etc/machine-krb` — if you want them gone).

## License

Dual-licensed under [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE),
at your option.
