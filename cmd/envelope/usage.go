package main

const (
	usageKeygen  = "envelope keygen  -out identity.txt"
	usageSplit   = "envelope split   -identity identity.txt -in secret.bin -out shards/ [-k 3] [-n 5]"
	usageRestore = "envelope restore -identity identity.txt -in shards/ -out secret.bin"
	usageAll     = usageKeygen + "\n" + usageSplit + "\n" + usageRestore + "\n"
)
