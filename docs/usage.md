# Envelope usage guide

Envelope turns one file into `n` encrypted shards, any `k` of which restore it.
It encrypts with age (X25519) first, then Reed–Solomon-codes the ciphertext, so
no shard contains plaintext.

Read the [v0 usage policy](../README.md#v0-usage-policy) before using it:
**v0 is for test material only.** Until a hardware identity exists, the identity
file is as stealable as the secret it protects.

## Install

```sh
go build -o envelope ./cmd/envelope
./envelope -version
./envelope --help
```

`-version` prints the Envelope build and the `age` and `reedsolomon` versions.
`--help` prints help.

## The things you keep

| Thing | What it is | If you lose it |
|---|---|---|
| Identity file | The only decryption key (native `keygen` identity) | **Everything is gone.** No recovery, no passphrase, no escrow. |
| Bundle | Hardware identity plus wrapped pin; see [The bundle](#the-bundle) | Every shard set is **unverifiable and unrestorable**, even with a working key. |
| Shards | `shard-00` … `shard-(n-1)` | Fine, as long as `k` survive intact. |
| `manifest.age` | Shard count, sizes, digests; encrypted and MAC'd to the identity | Restore refuses to run. Keep a copy next to **every** shard. |

Back the identity (or bundle) up separately from the shards. Anyone holding the
identity and `k` shards can restore; `(k, n)` is loss tolerance, not a
secret-sharing threshold. A hardware identity is two durable artifacts — the
bundle and the recovery recipient's key material — not one identity file.

## 1. Create an identity

```sh
envelope keygen -out identity.txt
```

- Writes one native age identity line, mode `0600`.
- Prints nothing on success.
- Refuses to overwrite: `identity file already exists` (exit 1).

## 2. Split a file

```sh
envelope split -identity identity.txt -in secret.bin -out shards/ -k 3 -n 5
```

| Flag | Required | Meaning |
|---|---|---|
| `-identity` | yes | Identity file from `keygen` |
| `-in` | yes | File to protect |
| `-out` | yes | Output directory; created `0700` if absent, must be empty if present |
| `-k` | no (default 3) | Shards needed to restore, `≥ 1` |
| `-n` | no (default 5) | Total shards, `k < n ≤ 256` |

Output, on stderr:

```
encrypted 4296 bytes
wrote 5 shards to shards/
```

The directory then holds:

```
shards/                 0700
  shard-00 … shard-04   0644, all the same size
  manifest.age          0644, written last
```

`manifest.age` is written only after every shard is synced, via a temporary
file that is renamed into place. A directory without it is an incomplete
split — delete it and run again. `keygen` syncs the identity file and its
directory before reporting success. Ctrl-C during split cancels before the
commit marker is published and removes any shard files already written.

### Distribute the shards

Copy each shard to a different place (disk, USB stick, machine) and put a copy
of `manifest.age` alongside each. The file name does not matter to restore, but
**the index does**: `shard-02` must come back as `shard-02`. Restore places
shards by name, and a shard under the wrong name simply fails its digest check.

Restore from those locations. There is no `cp` back into one directory, and
read-only media can be passed as `-in` in place:

```sh
envelope restore -identity identity.txt -in /mnt/a -in /mnt/b -in /mnt/c -out secret.bin
```

## 3. Restore

Point `-in` at a directory that holds at least `k` shards and a `manifest.age`:

```sh
envelope restore -identity identity.txt -in shards/ -out secret.bin
```

`-identity` may be repeated. Identities are tried in the order given.
`-in` may be repeated. Directories are searched in the order given; the first
usable copy of each shard wins. A `manifest.age` is needed in at least one of
them. Restore from the disks the shards already live on — there is no gather
step:

```sh
envelope restore -identity identity.txt -in /mnt/a -in /mnt/b -in /mnt/c -out secret.bin
```

| Flag | Required | Meaning |
|---|---|---|
| `-identity` | yes | The identity used for `split`; repeatable. Tried in the order given |
| `-in` | yes | Directory of shards; repeatable. A manifest is needed in at least one |
| `-out` | yes | Where to write the restored file |

Output, on stderr:

```
restored 4096 bytes to secret.bin
```

The result is mode `0600`. Envelope writes `secret.bin.partial` first, syncs it,
then renames it into place; on any failure or Ctrl-C the `.partial` is deleted.

Before anything is written, every shard is checked against the digests in the
manifest. Missing shards are skipped silently; corrupt ones and unusable
inputs (a directory or FIFO at a shard path) are reported and skipped:

```
failed digest at index 1
unusable shard at index 4
restored 4096 bytes to secret.bin
```

With two or more `-in` directories, the same lines name the path as given:

```
failed digest at index 1: /mnt/a/shard-01
unusable shard at index 4: /mnt/b/shard-04
restored 4096 bytes to secret.bin
```

When two or more `-in` values are given, each directory must exist, be a
directory, and be readable. A bad path exits 1 as `-in <path>: <reason>` and
writes no output. A single `-in` that does not exist still reports
`no manifest.age in the shard directory`.

As long as `k` shards pass, restore succeeds. A leftover special file at a
shard path, or a shard whose size is not the authenticated stripe length, is
not a restore failure.

> **`-out` is overwritten if it exists.** Only a leftover `.partial` blocks
> restore; an existing destination file is replaced without asking.

Restore to local storage. On macOS network mounts (SMB), `fsync` can silently
fall back to a weaker call.

## 4. Verify

```sh
envelope verify -identity identity.txt -in shards/
```

`-identity` may be repeated. Identities are tried in the order given.
`-in` may be repeated. Directories are searched in the order given; the first
usable copy of each shard wins. A `manifest.age` is needed in at least one of
them:

```sh
envelope verify -identity identity.txt -in /mnt/a -in /mnt/b -in /mnt/c
```

`restore` stops at the first usable copy of each shard, so checking every
stored copy is what `verify` is for. Over slow removable media that means
reading up to `d ×` the data — by design, and the price of the question it
answers.

| Flag | Required | Meaning |
|---|---|---|
| `-identity` | yes | The identity used for `split`; repeatable. Tried in the order given |
| `-in` | yes | Directory of shards; repeatable. A manifest is needed in at least one |

The identity is required because the manifest is encrypted. Verify writes
nothing: `-in` is not modified, it works on read-only media, and it decrypts
only in memory.

The report is on stdout, always `n + 4` lines. A `(3,5)` set with one missing
shard and one corrupt shard:

```
manifest ok: k=3 n=5
shard-00 ok
shard-01 missing
shard-02 corrupt
shard-03 ok
shard-04 ok
usable 3 of 5, need 3
payload ok: 4096 bytes
result: damaged
```

Each shard is `ok`, `missing`, or `corrupt`. The payload line is
`payload ok: B bytes`, `payload failed`, or `payload skipped` (when fewer than
`k` shards are usable). `result` is one of four classes:

| Result | Meaning | Exit |
|---|---|---|
| `healthy` | All `n` shards ok and the payload ok | 0 |
| `degraded` | At least `k` ok, some missing, none corrupt, payload ok | 0 |
| `damaged` | At least one shard corrupt, but the set still restores | 1 |
| `unrestorable` | Fewer than `k` shards ok, or the payload failed | 1 |

With one `-in`, `healthy` and `degraded` print nothing on stderr. With two or
more, `verify` names every rejected copy the walk reached — a rotten redundant
copy is visible here and invisible to `restore`. `damaged` names the failing
indices on stderr, then `shard set is damaged: at least one shard failed its
digest`. A manifest or identity failure prints nothing on stdout and the same
message restore would.

## Print the recipient

```sh
envelope recipient -identity identity.txt > identity.pub
envelope recipient -identity bundle.txt
```

Prints the public `age1` recipient of `-identity` to stdout. A file identity
prints one line. A bundle prints the whole recorded set, one per line, in
bundle order. Use it to label which identity owns a shard set, or to check the
identity against other age tools. It never prints the secret key. The identity
file is not modified.

A plugin identity stub carries no public key — only a serial, a slot, and a
short fingerprint — so Envelope cannot recover the recipient from the stub
alone. `envelope recipient -identity stub.txt` fails and points at
`envelope bind`. Get the string from the plugin's own listing:
`age-plugin-yubikey --list-all`.

## Full example

```sh
mkdir -p /tmp/envelope-demo && cd /tmp/envelope-demo
dd if=/dev/urandom of=secret.bin bs=1048576 count=1

envelope keygen  -out identity.txt
envelope split   -identity identity.txt -in secret.bin -out shards/ -k 3 -n 5
rm shards/shard-03 shards/shard-04          # lose two shards
envelope restore -identity identity.txt -in shards/ -out restored.bin
cmp secret.bin restored.bin && echo identical
```

## Help

```sh
envelope help
envelope help split
envelope split -h
```

`-h`, `-help` and `--help` are equivalent. `envelope help` matches root `-h`;
`envelope help split` matches `split -h`. Help goes to stdout and exits 0.

## Shell completion

```sh
eval "$(envelope completion bash)"
source <(envelope completion zsh)
envelope completion fish > ~/.config/fish/completions/envelope.fish
```

`envelope completion bash`, `zsh` or `fish` writes a completion script to
stdout and exits 0. On macOS bash 3.2, `eval` is required because
`source <(envelope completion bash)` (the form `envelope help completion`
prints) exits 0 without enabling completion. `pwsh` is also emitted; it is
not part of the contract.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (`verify` `healthy`/`degraded`); explicit help (`-h`, `-help`, `--help`); `help`; `help <command>`; `completion <shell>`; `-version`; `recipient` |
| 1 | Operation failed (`verify` `damaged`/`unrestorable`); the reason is on stderr |
| 2 | Bad usage: unknown command, missing flag, or invalid `(k, n)` |

stdout carries only what the operator asked a command to produce: version info,
help text, a completion script, recipient lines, and the verify report.
stderr carries status, diagnostics, and errors. Neither stream ever carries
payload or key material, and neither echoes a positional argument's value.

If `URFAVE_CLI_TRACING=on` is set when the process starts, the library writes
trace lines to stderr. The traces carry paths and `k`/`n`, never payload or
key material. It is a library debug switch, not an Envelope configuration
source.

If `AGEDEBUG=plugin` is set when the process starts, Envelope prints one
warning line on stderr before any command runs, then the age plugin client
tees both protocol directions to stderr. That includes any PIN, base64-encoded
in an `ok` stanza. It is a debug switch, not an Envelope configuration source,
and it is **unsafe with a real secret**.

## Hardware identities

An `age-plugin-*` identity is a line `AGE-PLUGIN-<NAME>-1…` that names an
external plugin binary (`age-plugin-<name>` on `PATH`). Envelope execs that
binary when it needs to unwrap a file; it never holds the private key.

Envelope never creates hardware keys. Generate or import them with the plugin
itself (`age-plugin-yubikey --generate`) or with `ykman piv keys import`, then
pass the identity file the plugin prints as `-identity`.

Any `age-plugin-*` works. YubiKey is the documented example, not a special case
in the tool.

### Two keys, one shard set

Listing `-identity` twice is supported. Identities are tried in the order
given, with native (file) identities first so a paper backup never waits on a
card. An absent key is skipped without asking for its PIN. One unreachable
key never blocks another: `restore -identity yk1.txt -identity yk2.txt` with
only YK2 plugged in succeeds, in either order.

### Install the plugin

Install `age-plugin-yubikey` from Homebrew, Nix, your distro package, or
`cargo install`. Do **not** send Linux operators to the v0.5.1 GitHub release
assets: that release ships darwin (arm64 and x86_64) and windows only, and has
**no Linux artifact**.

Linux and BSD need `pcscd` installed and running. macOS needs nothing extra.
On WSL, put the Windows-host plugin binary on the WSL `PATH`.

The plugin inherits Envelope's entire environment. Envelope execs whichever
`age-plugin-<name>` is first on `PATH`. The resolved absolute path is printed
on stderr the first time one launches, so a surprising binary is visible
rather than silent.

## Prompts and touches

Hardware identities prompt on the terminal (`/dev/tty`), never on stdout.

A run with no controlling terminal and an interactive identity is refused
before any plugin starts, with `this identity needs a PIN and there is no
terminal to ask on`, and writes nothing. A programmatic cancellation cannot
interrupt a blocked plugin, so refusing early is the guarantee. Envelope never
falls back to stdin, which may be the payload.

There is **no touch prompt for any key**, generated or imported. After five
seconds Envelope prints a wait line (`waiting on age-plugin-<name>…`). Touch
the key when you see it; that wait line is the only indication.

If the plugin cannot open the card it asks you to insert it. While another
identity is still untried, Envelope offers skip and defaults to skipping so
the next identity can run. On the last identity it presents the insert prompt
and waits. Envelope answers "plugged in" at most three times, then gives up
with `gave up waiting for age-plugin-<name> after 3 attempts` and tries any
remaining identities. That identity is skipped, not treated as a fatal error.

For fewer prompts, create or import the slot with `PinPolicy::Once` and
`TouchPolicy::Cached`. The policy must be set at creation or import: changing
it later has **no effect on existing slots** (age-plugin-yubikey
[issue #107](https://github.com/str4d/age-plugin-yubikey/issues/107)). An
imported key **always** prompts for a PIN, because the plugin can read neither
policy from an imported slot — so the recoverable configuration is the noisier
one.

Two caveats on those counts: `PinPolicy::Once`'s cached-PIN probe does not
work on the YubiKey 4 series, and `TouchPolicy::Cached` is a 15-second
**wall-clock** window, so reading cold USB media between two invocations can
cost a second touch.

### Recipient strings

A hardware identity's public recipient is an `age1…` string. Get it from the
plugin's own listing; for YubiKey that is `age-plugin-yubikey --list-all`.
Envelope never computes it from the identity stub.

The string is public. Encrypting to it does not need the card. Mixing a
hardware recipient with a paper (file-identity) recipient works: either
identity alone can restore.

### The bundle

A hardware identity is stored as one small **bundle** file you back up. It
holds identity lines, the recorded public recipient strings, a public
`mac_key_id`, and a pin — the 32-byte seed, encrypted to those recipients. It
holds no plaintext secret. A stolen bundle yields nothing, because the seed is
encrypted to hardware.

**Its loss makes every shard set unverifiable and therefore unrestorable even
with a working key.** The bundle and the recovery recipient's key material are
the two durable artifacts; losing the bundle is not the same as still having
the card.

The file is still a valid `age` identity file (`age -d -i bundle.txt` works):
metadata lives on `#` lines, and the pin is base64, not age armor. `mac_key_id`
is public metadata — 32 lowercase hex characters on the `envelope-mac-key-id`
line — so you can read a backup and confirm it is the right one without the
card. The seed is long-lived on purpose and is never regenerated: a silently
new seed would look, to you, like every shard set you own had been forged.

A v2 manifest is not readable by a pre-hardware Envelope. Back the bundle up
alongside the key material, and **do not roll back past this release after
splitting with a bundle**.

### bind

`bind` writes the bundle. It is not keygen-for-hardware: it creates **no key
material on a device**. `age-plugin-yubikey --generate` or `ykman piv keys
import` owns that. Envelope never drives the PIV applet, manages PINs, or
writes certificates.

Three modes. Exactly one of `-out` with `-identity`, `-bundle` with
`-add-recipient`, or `-bundle` with `-replace-identity`. A conflict or a
missing pair is usage (exit 2). None of the flags is required on its own,
because there are three shapes.

**Create** costs **0** plugin interactions (encryption is to recipient
strings only):

```sh
envelope bind -identity stub.txt -recipient age1yubikey1… -recipient age1… -out bundle.txt
```

**Add a recipient** re-wraps the **same** seed and costs **1** plugin
interaction (never mints a seed):

```sh
envelope bind -bundle bundle.txt -add-recipient age1…
```

**Replace the identity line** copies the pin ciphertext verbatim, leaves
recipients and `mac_key_id` untouched, and costs **0** plugin interactions:

```sh
envelope bind -bundle bundle.txt -replace-identity stub.txt
```

Create refuses to overwrite: `identity file already exists` (exit 1). The
file is mode `0600`, valid UTF-8, and holds no 32-byte cleartext secret.

#### The rotation trap

`-add-recipient` re-wraps the same seed so every existing *manifest* keeps
verifying, but age has no recipient rotation. Payloads already written remain
decryptable only by the original set. Adding a recipient for the *payload*
means a fresh `split`. See [issue #75](https://github.com/rootwarp/envelope/issues/75).

#### Imported-key recovery

The recoverable configuration is Envelope's recommendation, because a
generated-on-card key dies with the device. Generate a P-256 key offline,
`ykman piv keys import` it, generate a certificate, then
`age-plugin-yubikey --identity --slot N`. Bare `--identity` **hides** imported
keys: the gate is the certificate's Subject Organization attribute, not
attestation. An imported key cannot satisfy attestation, so the plugin reads
neither PIN nor touch policy and **always prompts for a PIN**. The recoverable
configuration is the noisier one.

Record, for each key: model, firmware (5.7+ preferred), serial, retired slot,
generated-on-card vs imported, PIN and touch policies — and that an imported
key's policies are unreadable. Get the recipient string from `--list` /
`--list-all`.

#### Replacement drill

Import the backed-up P-256 key into a replacement YubiKey, regenerate the
stub (`--identity --slot N`), then `envelope bind -replace-identity`. Every
existing shard set restores unchanged, with no re-encryption. The recipient
string is byte-identical (it is the public key); the stub is not, because it
embeds the device serial.

#### Indirection (not the default)

Someone who has decided rotation matters more than non-exportability can
encrypt the payload to a master X25519 identity and wrap that master to N
recipients. That pattern is documented here so the cost is visible, not so
it becomes the default.

**Cost to Goal #1 (the decryption key is non-exportable):** the decryption
key becomes a software scalar present in Envelope's address space at every
split and restore. One decryption of the bundle copies it, and the YubiKey
is never needed again. That converts non-exportable custody into a one-time
gate in front of an exportable key.

## Troubleshooting

| Message | Cause | Fix |
|---|---|---|
| `identity file already exists` | `keygen -out` points at an existing file | Choose another path; never overwrite a live identity |
| `identity file is invalid` | Not an age identity file | Point `-identity` at the `keygen` output |
| `identity bundle version is not supported` | The first non-empty line is not `# envelope-bundle: v1` | Use a v1 bundle; a newer format needs a newer Envelope |
| `identity bundle has an unknown or malformed field` | An `# envelope-…` line is unknown or not `# envelope-<key>: <value>` | Restore a known-good copy of the bundle; do not hand-edit envelope fields |
| `identity bundle exceeds size limit` | The file is larger than 64 KiB | Use another copy of the bundle; a real bundle is small |
| `identity bundle requires at least one recipient` | The bundle would record no public recipient, so it could not split | Get the public recipient from the plugin's own listing (`age-plugin-yubikey --list-all` for YubiKey) and record it |
| `identity bundle pin is corrupt` | The wrapped seed does not match this bundle's `mac_key_id` | Restore a known-good copy of the bundle; do not regenerate a seed |
| `plugin identity has no local recipient string` | A plugin identity stub carries no public key | Record the recipient with `envelope bind`, or get it from the plugin's own listing (`age-plugin-yubikey --list-all` for YubiKey) |
| `no identity bundle in this run; create one with envelope bind` | this shard set was made with a bundle; load it with `-identity bundle.txt` | Point `-identity` at the bundle `envelope bind` wrote |
| `two bundles in one run record different MAC keys; pass one` | two bundles in one run record different MAC keys; pass one | Pass one bundle, or two copies of the same one |
| `age plugin binary is not installed: age-plugin-…` | The plugin named by the identity is not on `PATH` | Install it with Homebrew, Nix, your distro package, or `cargo install`; confirm `age-plugin-<name>` is on `PATH` |
| `age plugin failed: age-plugin-…` | The plugin refused the unwrap (no card, wrong card or slot, wrong PIN, blocked PIN, AEAD failure) | Plug in the right key, check the slot, retry with the correct PIN; a wrong PIN is fatal and is not retried |
| `age plugin protocol error: age-plugin-…` | The plugin exited non-zero or broke the age plugin protocol | Reinstall the plugin from Homebrew, Nix, the distro package, or `cargo install`; confirm `age-plugin-<name> --version` runs |
| `algorithm error` from `age-plugin-yubikey --list` / `--generate` / `--identity` | A PIV slot (any slot the plugin enumerates) holds a key with an unsupported algorithm. Decryption of existing files still works; setup breaks. [age-plugin-yubikey#241](https://github.com/str4d/age-plugin-yubikey/issues/241) on v0.5.1 | Use a slot the plugin supports, or retire the offending slot key; do not treat this as an Envelope decrypt failure |
| `Could not open YubiKey` / exclusive-access errors while `yubikey-agent` is running | `yubikey-agent` holds exclusive PC/SC access to the card. [age-plugin-yubikey#136](https://github.com/str4d/age-plugin-yubikey/issues/136) | Stop `yubikey-agent` (and any other exclusive PC/SC client) before Envelope |
| Plugin sees Envelope's whole environment | `cmd.Env` is unset, so the child inherits every variable Envelope has, including anything a wrapper exported | Treat the plugin process as Envelope-equivalent; do not rely on hiding secrets from it by environment |
| `output directory is not empty: …` | `split -out` has files in it | Use a new or empty directory |
| `k must be at least 1` / `n must be greater than k` / `n must not exceed 256` | Invalid `(k, n)` | Pick `1 ≤ k < n ≤ 256` |
| `no manifest.age in the shard directory: …` | `manifest.age` wasn't copied into `-in` | Copy any surviving copy of the manifest in |
| `a .partial file from a previous run is present: …` | An earlier restore was killed hard (e.g. power loss) | Delete the `.partial` — it may hold plaintext — then retry |
| `output written but directory could not be synced: …` | The restored file was renamed into place, then directory fsync failed | Keep the output; treat crash durability of the directory entry as uncertain |
| `need at least K usable shards, have H` | Fewer than `k` shards survived the digest check | Find more shards; check that names/indices are right |
| `unusable shard at index N` | That path exists but is not a usable regular file | Remove the stray directory/FIFO or ignore it if `k` others are good |
| `result: damaged` | At least one shard is corrupt, but `k` usable shards remain | Replace the corrupt shards; restore still works |
| `result: unrestorable` | Fewer than `k` shards are usable, or the reconstructed payload failed | Find more intact shards; a payload failure means the reconstructed ciphertext is bad |
| `shard set is damaged: at least one shard failed its digest` | `verify` found a digest failure on a still-restorable set | Same as `result: damaged`; stderr names the failing indices |
| `H of N shards matched the manifest — the manifest may not belong to this shard set` | The manifest is from a different split than the shards | Use the `manifest.age` that was written with these shards |
| `no identity matched the file: …` | Wrong identity for this manifest | Use the identity the split was made with |
| `conflicting manifests: A/manifest.age and B/manifest.age describe different shard sets` | Two `-in` directories hold authentic manifests for different splits | Use directories from the same split; exits 1 |
| `-in <path>: <reason>` | A `-in` path does not exist, is not a directory, or cannot be read | Only when two or more `-in` values are given; fix the path. A single missing `-in` still reports `no manifest.age…` |
| `manifest.age exceeds size limit: …` | `manifest.age` is far larger than a real manifest | Use another copy of the manifest |
| `malformed age file: …/manifest.age` | `manifest.age` is not age ciphertext (wrong file, truncated header) | Use another copy of the manifest |
| `failed to decrypt and authenticate payload chunk, file may be corrupted or tampered with: …/manifest.age` | `manifest.age` is damaged or was modified | Use another copy of the manifest |
| `unsupported manifest version` | this shard set was written by a newer binary; a v2 manifest is not readable by a pre-hardware Envelope — upgrade rather than downgrade | Upgrade Envelope |
| `manifest MAC key id mismatch` | this manifest was MAC'd with a pin you do not have (hint; the field is attacker-chosen) | Load the identity bundle used at split |
| `manifest MAC mismatch` | this manifest is forged or damaged (verdict) | Do not restore from this set; use another copy of the manifest only if you trust it |
| `Required flag(s) "…" not set` | A required flag is missing | Pass every flag listed in that command's help |
| `flag provided but not defined: -X` | Unknown flag | Drop it; see that command's help for the flags it accepts |
| `unexpected positional argument` | Extra argument after the flags | Remove it |
| `did you mean "…"?` | Command name is close to a known command | Use the suggested command |

Interactive identities need a terminal; with none, the run is refused before any plugin starts, with `this identity needs a PIN and there is no terminal to ask on`.

A failed restore never leaves a partial output file behind.
