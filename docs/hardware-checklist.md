# Hardware acceptance checklist

Device-only items. Execute once; record results in the plan folder. A failure is a blocker.

1. `age-plugin-yubikey --version` on `PATH`; record the version. On Linux, `pcscd` is running.

2. Record, for each key used: model, firmware version (5.7+ preferred), serial, PIV slot (retired slot N), whether the key was generated on-card or imported, and its PIN and touch policies. For an imported key, note that the plugin cannot read either policy and will prompt for a PIN regardless, and will not announce a touch.

3. `age-plugin-yubikey --identity --slot N > stub.txt` for an imported key (bare `--identity` hides it); `--identity` alone for a generated one. Record the recipient string from `--list` / `--list-all`.

4. `envelope bind -identity stub.txt -recipient <yk-recipient> -recipient <paper-recipient> -out bundle.txt`; assert mode `0600`, valid UTF-8, no 32-byte cleartext secret, and `age -d -i bundle.txt` works against an Envelope-written `manifest.age`.

5. `envelope recipient -identity bundle.txt` prints the recorded set, never `<identity-based recipient>`.

6. Card-free split: with the key unplugged, `split` must still encrypt the payload and must stop at the pin unwrap with a card-required diagnosis; then plug in and count PIN prompts and touches.

7. `split` a ≥ 1 MiB file at `(3,5)`, delete two shards, `restore`, `cmp` identical — on a generated-on-card key **and** an imported key.

8. count plugin interactions for `restore` and `verify` and record them against architecture §6.3; repeat `verify` with two `-in` directories and record whether the prompt count grew

9. Backup proven: a `(3,5)` set split to `[YK1, YK2, paper]` restores from each of the three independently, with the other two absent.

10. `restore -identity yk1.txt -identity yk2.txt` with only YK2 present must succeed and must not prompt for YK1's PIN; then swap the order and repeat.

11. Replacement drill. Import the backed-up P-256 key into a second YubiKey, regenerate the stub, `envelope bind -replace-identity`, and restore an existing shard set with no re-encryption. Confirm the recipient string is byte-identical to the original.

12. `ykman piv reset` a spare key; `restore` and `verify` fail closed with a named diagnosis and write nothing.

13. a manifest and shard set minted by a party holding only the recipient set is rejected on the MAC before reconstruction

14. Run the full pipeline with stdin/stdout/stderr redirected and no controlling terminal via `setsid`/`nohup`: exits non-zero within seconds with `this identity needs a PIN and there is no terminal to ask on`, having written nothing.

15. On a real terminal with stdin **and** stdout redirected, the PIN prompt still appears and is answerable.

16. During a touch wait, Ctrl-C leaves no `.partial`, no `-out`, no partial shard set, and no `age-plugin-yubikey` process (`pgrep age-plugin`).

17. `AGEDEBUG=plugin` emits Envelope's warning before any plugin starts; confirm on a throwaway PIN that the PIN does appear on stderr.

18. Over a marker-bearing input with a real PIN, grep every shard, every stream and every log for the marker and for the PIN.

19. The committed pre-initiative shard set restores byte-identically, verifies `healthy`, and costs zero plugin interactions.
