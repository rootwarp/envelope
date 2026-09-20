# Hardware acceptance checklist

Device-only items. Execute once; record results in the plan folder. A failure is a blocker.

1. `age-plugin-yubikey --version` on `PATH`; record the version. On Linux, `pcscd` is running.

10. `restore -identity yk1.txt -identity yk2.txt` with only YK2 present must succeed and must not prompt for YK1's PIN; then swap the order and repeat.

12. `ykman piv reset` a spare key; `restore` and `verify` fail closed with a named diagnosis and write nothing.

13. a manifest and shard set minted by a party holding only the recipient set is rejected on the MAC before reconstruction

14. Run the full pipeline with stdin/stdout/stderr redirected and no controlling terminal via `setsid`/`nohup`: exits non-zero within seconds with `this identity needs a PIN and there is no terminal to ask on`, having written nothing.

15. On a real terminal with stdin **and** stdout redirected, the PIN prompt still appears and is answerable.

17. `AGEDEBUG=plugin` emits Envelope's warning before any plugin starts; confirm on a throwaway PIN that the PIN does appear on stderr.

18. Over a marker-bearing input with a real PIN, grep every shard, every stream and every log for the marker and for the PIN.

19. The committed pre-initiative shard set restores byte-identically, verifies `healthy`, and costs zero plugin interactions.
