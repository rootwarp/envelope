# envelop

Go CLI: encrypt a file with age (X25519), Reed–Solomon split the ciphertext, restore from any k of n.

Layout follows the usual Go CLI shape (`cmd/`, `internal/`). Phase 1 implementation is in issues #2–#6; this commit is directory skeleton only.

```
envelop keygen  -out identity.txt
envelop split   -identity identity.txt -in secret.bin -out shards/
envelop restore -identity identity.txt -in shards/ -out secret.bin
```
