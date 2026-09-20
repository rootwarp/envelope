package main

const (
	usageKeygen      = "envelope keygen  -out identity.txt"
	usageBindCreate  = "envelope bind    -identity stub.txt -recipient age1... -out bundle.txt"
	usageBindAdd     = "envelope bind    -bundle bundle.txt -add-recipient age1..."
	usageBindReplace = "envelope bind    -bundle bundle.txt -replace-identity stub.txt"
	usageBind        = usageBindCreate + "\n" + usageBindAdd + "\n" + usageBindReplace
	usageSplit       = "envelope split   -identity identity.txt -in secret.bin -out shards/ [-k 3] [-n 5]"
	usageRestore     = "envelope restore -identity identity.txt -in shards/ -out secret.bin"
	usageVerify      = "envelope verify -identity identity.txt -in shards/"
	usageRecipient   = "envelope recipient -identity identity.txt"
	usageHelp        = "envelope help [command]"
	usageCompletion  = "envelope completion bash|zsh|fish"
	usageVersion     = "envelope -version"
	usageAll         = usageKeygen + "\n" + usageBind + "\n" + usageSplit + "\n" + usageRestore + "\n" + usageVerify + "\n" + usageRecipient + "\n" + usageHelp + "\n" + usageCompletion + "\n" + usageVersion + "\n"

	summaryRoot      = "encrypt one file with age, then Reed-Solomon it into n shards"
	summaryKeygen    = "create an identity file"
	summaryBind      = "create or update an identity bundle"
	summarySplit     = "encrypt a file and write n shards"
	summaryRestore   = "restore a file from k shards"
	summaryVerify    = "check whether a shard set would restore"
	summaryRecipient = "print the public recipient of an identity file"
	summaryHelp      = "show help for envelope or one command"

	// urfave has no Examples field; Description keeps newlines (research/04 §1).
	descriptionKeygen = `Writes one native age identity line, mode 0600.
Prints nothing on success and refuses to overwrite: identity file already exists (exit 1).
Losing the identity is unrecoverable.

Examples:
  envelope keygen -out identity.txt`
	descriptionBind = `Creates or updates an identity bundle. Bind creates no key material on a device: generate or import keys with the plugin itself, then pass the identity file it prints.

Three modes; exactly one of:
  -identity FILE -recipient AGE1 -out FILE   create a bundle (0 plugin interactions; encryption is to recipient strings)
  -bundle FILE -add-recipient AGE1           re-wrap the same seed to more recipients (1 plugin interaction; never mints a seed)
  -bundle FILE -replace-identity FILE        swap identity lines; pin ciphertext copied verbatim (0 plugin interactions)

-identity, -recipient, -add-recipient and -replace-identity may be repeated.
Prints nothing on success. Create refuses to overwrite: identity file already exists (exit 1).
A conflict or a missing pair is usage (exit 2).

Examples:
  envelope bind -identity stub.txt -recipient age1... -out bundle.txt
  envelope bind -bundle bundle.txt -add-recipient age1...
  envelope bind -bundle bundle.txt -replace-identity stub.txt`
	descriptionSplit = `Protects -in using the identity from keygen.
Constraint: 1 ≤ k < n ≤ 256. -out must be absent or empty; created 0700 if absent.
manifest.age is written last. A directory without it is an incomplete split — delete it and run again.

Examples:
  envelope split -identity identity.txt -in secret.bin -out shards/ -k 3 -n 5`
	descriptionRestore = `Restores a file from at least k shards and a manifest.age in -in.
-identity may be repeated. Identities are tried in the order given.
-in may be repeated. Directories are searched in the order given; the first usable copy of each shard wins. A manifest is needed in at least one of them.
The result is mode 0600. An existing -out is overwritten.
Only a leftover .partial blocks restore; an existing destination file is replaced without asking.

Examples:
  envelope restore -identity identity.txt -in shards/ -out secret.bin
  envelope restore -identity identity.txt -in /mnt/a -in /mnt/b -in /mnt/c -out secret.bin`
	descriptionVerify = `Checks whether a shard set would restore, without writing a file.
healthy and degraded exit 0; damaged and unrestorable exit 1 with the report still on stdout.
The identity is required because the manifest is encrypted. -in is not modified.
-identity may be repeated. Identities are tried in the order given.
-in may be repeated. Directories are searched in the order given; the first usable copy of each shard wins. A manifest is needed in at least one of them.
restore stops at the first usable copy of each shard, so checking every stored copy is what verify is for.

Examples:
  envelope verify -identity identity.txt -in shards/
  envelope verify -identity identity.txt -in /mnt/a -in /mnt/b -in /mnt/c`
	descriptionRecipient = `Prints the public age1 recipient of -identity.
A file identity prints one line. A bundle prints the recorded set, one per line, in bundle order.
A plugin identity stub has no local recipient; record it with bind, or get it from the plugin's own listing.
Never prints the secret key. The identity file is not modified.

Examples:
  envelope recipient -identity identity.txt
  envelope recipient -identity bundle.txt`
)
