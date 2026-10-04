package pipeline

import "testing"

// Package-level acceptance cases (round trip, missing shards, one corrupt
// shard, tampered MAC, destination mode, late close, leftover .partial).
// The command-level twins live in cmd/envelope/acceptance_test.go.

func TestAcceptance_RoundTrip1MiB(t *testing.T) {
	// Synthetic crypto/rand, never a mnemonic-shaped fixture.
	assertRestoreRoundTrip(t, 1<<20)
}

func TestAcceptance_TwoShardsDeleted(t *testing.T) {
	TestRestoreWithTwoShardsDeleted(t)
}

func TestAcceptance_OneCorruptShard(t *testing.T) {
	TestRestoreWithOneCorruptShard(t)
}

// TestAcceptance_TamperedMAC covers a tampered MAC.
//
// Contributing tests: TestOpenRejectsAlteredDigestByte (package-level HMAC
// reject in internal/manifest) and TestRestoreTamperedMACEndToEnd (restore
// fails closed before reconstruction). Two exist because Open's MAC check
// does not prove restore's ordering — reconstruction must not run — and
// restore's e2e path does not prove Open itself fails closed on a bad MAC.
func TestAcceptance_TamperedMAC(t *testing.T) {
	TestRestoreTamperedMACEndToEnd(t)
}

func TestAcceptance_RestoreDestMode0600(t *testing.T) {
	TestRestoreDestinationMode(t)
}

// TestAcceptance_ForgottenClose covers a ciphertext that was never closed.
//
// Contributing tests: TestCloselessCiphertextFailsDecrypt (crypt-level
// Close-less ciphertext) and TestForgottenCloseFailsRestore (e2e).
// Two exist because the bug lives in crypt.Encrypt — unguarded if only the
// e2e test exists — while only the e2e test proves restore propagates the
// copy error rather than renaming truncated plaintext.
func TestAcceptance_ForgottenClose(t *testing.T) {
	TestForgottenCloseFailsRestore(t)
}

// TestAcceptance_LeftoverPartial is the leftover .partial half.
// Pair with TestAcceptance_PreexistingIdentity (internal/key). They cannot
// be one test: ErrPartialExists and ErrIdentityExists are different refusals.
//
// Contributing tests: TestRestoreLeftoverPartialRefused and
// TestCreateRefusesExisting. Two exist because the identity half is
// O_EXCL in key.Create and the .partial half is the leftover pre-check in
// pipeline.Restore; neither package can see the other refusal.
func TestAcceptance_LeftoverPartial(t *testing.T) {
	TestRestoreLeftoverPartialRefused(t)
}
