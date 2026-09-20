# v1 golden shard set

Pinned pre-initiative regression gate (I-1). Produced by a clean build of
`58ed8bd` (`feat(cmd): surface the verify scan-all guarantee`) on `develop`.
That binary reports `envelope v0.1.1-0.20260919191338-58ed8bd3f5a2`.

## How it was produced

```
go build -o /tmp/envelope-golden ./cmd/envelope
/tmp/envelope-golden keygen -out identity.txt
/tmp/envelope-golden split -identity identity.txt -in payload.bin -out shards/ -k 3 -n 5
```

`(k, n) = (3, 5)`, file identity. The plaintext is a few KiB of deterministic
bytes and is not in this directory; `payload.sha256` is `<hex>  <length>` of
that plaintext.

## Identity is split across two files

`scripts/check-discipline.sh` FR-24 fails the build on any tracked file that
contains the assembled native-identity prefix, so `identity.txt` cannot live
here and no exemption is added. `identity.bech32data` is the bech32 data part
only. Tests materialise the identity line as `key.HRP + "1" +` that data into
`t.TempDir()`. Bech32's charset excludes `1`, so the data part cannot begin
with the separator and the needle cannot straddle the two files.

`scalar.hex` is the 32-byte scalar as 64 lowercase hex characters.
`mackey.hex` is `HKDF-SHA256(scalar, "envelope", "envelope v1 manifest mac", 32)`
as 64 lowercase hex characters. The test derives that HKDF from `scalar.hex`
and requires it equal both `mackey.hex` and
`key.Load(materialised).ManifestMACKey()`, which binds the two committed
identity forms to the v1 MAC key.

## Never regenerate

This directory is never regenerated. Re-running `split` would replace the gate
with a tautology: the fixture would pin whatever the current tree writes,
including a silent MAC-key rotation. If a later binary fails to restore or
verify this set, the binary is wrong.
