# envelope

Envelope is a Go CLI that encrypts one opaque file with age (X25519), then
Reed–Solomon-codes the ciphertext into `n` shards so any `k` of them restore the
original. Encrypt-then-code: no shard, and no losing subset of shards, contains
plaintext.

See [docs/usage.md](docs/usage.md) for the full usage guide.

v0 is local files only: `keygen`, `split`, `restore`, `recipient`. Build with
`go build -o envelope ./cmd/envelope`.

## v0 usage policy

**No real wallet secret goes through v0 until a hardware identity exists.** v0
is exercised with **test material only**. Until an age-plugin / YubiKey identity
exists, the identity file is exactly as stealable as the mnemonic it protects,
so v0's threat model covers durability, not key custody.

## Identity loss is unrecoverable

Losing the identity file is total and permanent. There is no passphrase
fallback, no recovery, and no escrow. Every shard ever produced from that
identity becomes a durable paperweight, forever. Back the identity up separately
from every shard — that is a copy of the only key, not a way to reconstruct it.

## `(k, n)` is availability, not a Shamir threshold

Anyone with the identity and any `k` shards restores. Anyone without the
identity restores nothing. `(k, n)` is how many shards you can lose, not a
secret-sharing threshold. Three shards from a `(3,5)` split are not enough on
their own.

## Round trip

From a clone, with Go as in `go.mod`. This is a ≥ 1 MiB file at `(3,5)`, two
shards deleted, then a byte-identical restore.

```sh
go build -o envelope ./cmd/envelope

mkdir -p /tmp/envelope-demo
dd if=/dev/urandom of=/tmp/envelope-demo/secret.bin bs=1048576 count=1

./envelope keygen -out /tmp/envelope-demo/identity.txt
./envelope split -identity /tmp/envelope-demo/identity.txt -in /tmp/envelope-demo/secret.bin -out /tmp/envelope-demo/shards/ -k 3 -n 5
rm /tmp/envelope-demo/shards/shard-03 /tmp/envelope-demo/shards/shard-04
./envelope restore -identity /tmp/envelope-demo/identity.txt -in /tmp/envelope-demo/shards/ -out /tmp/envelope-demo/restored.bin
cmp /tmp/envelope-demo/secret.bin /tmp/envelope-demo/restored.bin
```

`cmp` prints nothing and exits 0 when the restored file is byte-identical.

## On-disk layout

```
<identity-path>          # 0600, native age X25519 identity line
<out-dir>/               # 0700
  shard-00 … shard-(n-1) # 0644, positional; the index is the identity, not the name
  manifest.age           # 0644, written LAST — this is the commit marker
<restore-out>.partial    # 0600, unlinked on any failure
<restore-out>            # 0600 after rename
```

## Restore to local storage

Restore onto local storage. On darwin, Go's `Sync()` is `F_FULLFSYNC` with an
`ENOTSUP` fallback to plain `fsync` on SMB and some network mounts, so a
`Sync()` that "succeeded" there may have been the weaker call and the durability
sequence is then weaker than it looks. macOS extended ACLs are invisible to the
mode checks Envelope makes.

## Commands

```
envelope keygen  -out identity.txt
envelope split   -identity identity.txt -in secret.bin -out shards/ [-k 3] [-n 5]
envelope restore -identity identity.txt -in shards/ -out secret.bin
envelope recipient -identity identity.txt
envelope help [command]
envelope completion bash|zsh|fish
envelope -version
```

`envelope <command> -h` prints help.
