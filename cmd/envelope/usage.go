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
)
