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
```

`-version` prints the Envelope build and the `age` and `reedsolomon` versions.

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

## 3. Restore

Gather at least `k` shards and a `manifest.age` into one directory, then:

```sh
envelope restore -identity identity.txt -in shards/ -out secret.bin
```

| Flag | Required | Meaning |
|---|---|---|
| `-identity` | yes | The identity used for `split` |
| `-in` | yes | Directory holding `manifest.age` and the surviving shards |
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

As long as `k` shards pass, restore succeeds. A leftover special file at a
shard path, or a shard whose size is not the authenticated stripe length, is
not a restore failure.

> **`-out` is overwritten if it exists.** Only a leftover `.partial` blocks
> restore; an existing destination file is replaced without asking.

Restore to local storage. On macOS network mounts (SMB), `fsync` can silently
fall back to a weaker call.

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

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Operation failed; the reason is on stderr |
| 2 | Bad usage: unknown command, missing flag, or invalid `(k, n)` |

stdout is used only by `-version`. Status lines and errors go to stderr, and no
command ever prints file contents or key material.

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
| `H of N shards matched the manifest — the manifest may not belong to this shard set` | The manifest is from a different split than the shards | Use the `manifest.age` that was written with these shards |
| `no identity matched the file: …` | Wrong identity for this manifest | Use the identity the split was made with |
| `manifest.age exceeds size limit: …` | `manifest.age` is far larger than a real manifest | Use another copy of the manifest |
| `malformed age file: …/manifest.age` | `manifest.age` is not age ciphertext (wrong file, truncated header) | Use another copy of the manifest |
| `failed to decrypt and authenticate payload chunk, file may be corrupted or tampered with: …/manifest.age` | `manifest.age` is damaged or was modified | Use another copy of the manifest |

A failed restore never leaves a partial output file behind.
