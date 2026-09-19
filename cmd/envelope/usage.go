package main

const (
	usageKeygen  = "envelope keygen  -out identity.txt"
	usageSplit   = "envelope split   -identity identity.txt -in secret.bin -out shards/ [-k 3] [-n 5]"
	usageRestore = "envelope restore -identity identity.txt -in shards/ -out secret.bin"
	usageAll     = usageKeygen + "\n" + usageSplit + "\n" + usageRestore + "\n"
	usageHelp    = "envelope help [command]"

	summaryRoot    = "encrypt one file with age, then Reed-Solomon it into n shards"
	summaryKeygen  = "create an identity file"
	summarySplit   = "encrypt a file and write n shards"
	summaryRestore = "restore a file from k shards"
	summaryHelp    = "show help for envelope or one command"

	// urfave has no Examples field; Description keeps newlines (research/04 §1).
	descriptionKeygen = `Writes one native age identity line, mode 0600.
Prints nothing on success and refuses to overwrite: identity file already exists (exit 1).
Losing the identity is unrecoverable.

Examples:
  envelope keygen -out identity.txt`
	descriptionSplit = `Protects -in using the identity from keygen.
Constraint: 1 ≤ k < n ≤ 256. -out must be absent or empty; created 0700 if absent.
manifest.age is written last. A directory without it is an incomplete split — delete it and run again.

Examples:
  envelope split -identity identity.txt -in secret.bin -out shards/ -k 3 -n 5`
	descriptionRestore = `Restores a file from at least k shards and a manifest.age in -in.
The result is mode 0600. An existing -out is overwritten.
Only a leftover .partial blocks restore; an existing destination file is replaced without asking.

Examples:
  envelope restore -identity identity.txt -in shards/ -out secret.bin`
)
