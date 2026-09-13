package pipeline

import "testing"

// FR-25 items 1, 2, 3, 6, 8, 9, 11 (.partial). Map: cmd/envelope/acceptance_test.go.

func TestAcceptance_RoundTrip1MiB(t *testing.T) {
	// Synthetic crypto/rand, never a mnemonic-shaped fixture (FR-19).
	assertRestoreRoundTrip(t, 1<<20)
}

func TestAcceptance_TwoShardsDeleted(t *testing.T) {
	TestRestoreWithTwoShardsDeleted(t)
}

func TestAcceptance_OneCorruptShard(t *testing.T) {
	TestRestoreWithOneCorruptShard(t)
}

// TestAcceptance_TamperedMAC is FR-25 item 6.
//
// Contributing tests: TestOpenRejectsAlteredDigestByte (M4.2, package-level
// HMAC reject in internal/manifest) and TestRestoreTamperedMACEndToEnd (M5b.3,
// restore fails closed before reconstruction). Two exist because Open's MAC
// check does not prove restore's ordering — reconstruction must not run — and
// restore's e2e path does not prove Open itself fails closed on a bad MAC.
func TestAcceptance_TamperedMAC(t *testing.T) {
	TestRestoreTamperedMACEndToEnd(t)
}

func TestAcceptance_RestoreDestMode0600(t *testing.T) {
	TestRestoreDestinationMode(t)
}

// TestAcceptance_ForgottenClose is FR-25 item 9.
//
// Contributing tests: TestCloselessCiphertextFailsDecrypt (M2.3, crypt-level
// Close-less ciphertext) and TestForgottenCloseFailsRestore (M5b.4, e2e).
// Two exist because the bug lives in crypt.Encrypt — unguarded if only the
// e2e test exists — while only the e2e test proves restore propagates the
// copy error rather than renaming truncated plaintext (plan R5).
func TestAcceptance_ForgottenClose(t *testing.T) {
	TestForgottenCloseFailsRestore(t)
}

// TestAcceptance_LeftoverPartial is FR-25 item 11's .partial half.
// Pair with TestAcceptance_PreexistingIdentity (internal/key). They cannot
// be one test: ErrPartialExists and ErrIdentityExists are different refusals
// sharing one FR-25 bullet.
//
// Contributing tests: TestRestoreLeftoverPartialRefused (M5b.1) and
// TestCreateRefusesExisting (M1.2). Two exist because the identity half is
// O_EXCL in key.Create and the .partial half is the leftover pre-check in
// pipeline.Restore; neither package can see the other refusal.
func TestAcceptance_LeftoverPartial(t *testing.T) {
	TestRestoreLeftoverPartialRefused(t)
}
