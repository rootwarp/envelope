# Hardware acceptance checklist

Device-only items. Execute once; record results in the plan folder. A failure is a blocker.

1. `age-plugin-yubikey --version` on `PATH`; record the version. On Linux, `pcscd` is running.

12. `ykman piv reset` a spare key; `restore` and `verify` fail closed with a named diagnosis and write nothing.

15. On a real terminal with stdin **and** stdout redirected, the PIN prompt still appears and is answerable.

18. Over a marker-bearing input with a real PIN, grep every shard, every stream and every log for the marker and for the PIN.

19. The committed pre-initiative shard set restores byte-identically, verifies `healthy`, and costs zero plugin interactions.
