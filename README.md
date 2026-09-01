# envelop

Protect high-value secrets (blockchain wallet keys and mnemonics): **encrypt first** with age (X25519), then **Reed–Solomon** split the ciphertext so shards can live apart and any `k` of `n` restore.

Layout: `cmd/envelop`, `internal/{key,crypt,erasure,manifest,pipeline}`. Phase 1 implementation is issues #2–#6. YubiKey identity is later.

```
envelop keygen  -out identity.txt
envelop split   -identity identity.txt -in secret.bin -out shards/
envelop restore -identity identity.txt -in shards/ -out secret.bin
```
