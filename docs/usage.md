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

## The three things you keep

| Thing | What it is | If you lose it |
|---|---|---|
| Identity file | The only decryption key | **Everything is gone.** No recovery, no passphrase, no escrow. |
| Shards | `shard-00` … `shard-(n-1)` | Fine, as long as `k` survive intact. |
| `manifest.age` | Shard count, sizes, digests; encrypted and MAC'd to the identity | Restore refuses to run. Keep a copy next to **every** shard. |

Back the identity up separately from the shards. Anyone holding the identity
and `k` shards can restore; `(k, n)` is loss tolerance, not a secret-sharing
threshold.

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

`-in` may be repeated. Directories are searched in the order given; the first
usable copy of each shard wins. A `manifest.age` is needed in at least one of
them. Restore from the disks the shards already live on — there is no gather
step:

```sh
envelope restore -identity identity.txt -in /mnt/a -in /mnt/b -in /mnt/c -out secret.bin
```

| Flag | Required | Meaning |
|---|---|---|
| `-identity` | yes | The identity used for `split` |
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
| `-identity` | yes | The identity used for `split` |
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
```

Prints the public `age1` recipient of `-identity`, one line, to stdout. Use it
to label which identity owns a shard set, or to check the identity against
other age tools. It never prints the secret key. The identity file is not
modified.

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
help text, a completion script, the recipient string, and the verify report.
stderr carries status, diagnostics, and errors. Neither stream ever carries
payload or key material, and neither echoes a positional argument's value.

If `URFAVE_CLI_TRACING=on` is set when the process starts, the library writes
trace lines to stderr. The traces carry paths and `k`/`n`, never payload or
key material. It is a library debug switch, not an Envelope configuration
source.

## Troubleshooting

| Message | Cause | Fix |
|---|---|---|
| `identity file already exists` | `keygen -out` points at an existing file | Choose another path; never overwrite a live identity |
| `identity file is invalid` | Not an age identity file | Point `-identity` at the `keygen` output |
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
| `Required flag(s) "…" not set` | A required flag is missing | Pass every flag listed in that command's help |
| `flag provided but not defined: -X` | Unknown flag | Drop it; see that command's help for the flags it accepts |
| `unexpected positional argument` | Extra argument after the flags | Remove it |
| `did you mean "…"?` | Command name is close to a known command | Use the suggested command |

Interactive identities need a terminal; with none, the run is refused before any plugin starts.

A failed restore never leaves a partial output file behind.
