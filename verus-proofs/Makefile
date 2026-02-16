# paraxiom-qssh Verus Tier 2: Functional Correctness Proofs
#
# ~20 proofs across 4 files verifying:
#   - Transport frame invariants (768-byte quantum frame)
#   - KDF key derivation correctness (HKDF + SHA3)
#   - ML-KEM encapsulation/decapsulation properties
#   - Handshake protocol framing & bounds
#
# Tier 2 verification (Kani → **Verus** → Lean 4).
# Run: make -C verus-proofs/

VERUS_HOME ?= $(HOME)/.verus
VERUS      ?= $(VERUS_HOME)/verus

PROOFS = transport_proofs kdf_proofs mlkem_proofs handshake_proofs

.PHONY: all $(PROOFS) summary clean

all: $(PROOFS)
	@echo ""
	@echo "════════════════════════════════════════════════════"
	@echo "  All paraxiom-qssh Verus Tier 2 proofs verified."
	@echo "════════════════════════════════════════════════════"

transport_proofs:
	@echo "── Verifying transport_proofs.rs (quantum frame invariants)..."
	@$(VERUS) transport_proofs.rs
	@echo "   ✓ transport_proofs: 6 verified"

kdf_proofs:
	@echo "── Verifying kdf_proofs.rs (key derivation correctness)..."
	@$(VERUS) kdf_proofs.rs
	@echo "   ✓ kdf_proofs: 4 verified"

mlkem_proofs:
	@echo "── Verifying mlkem_proofs.rs (ML-KEM properties)..."
	@$(VERUS) mlkem_proofs.rs
	@echo "   ✓ mlkem_proofs: 4 verified"

handshake_proofs:
	@echo "── Verifying handshake_proofs.rs (handshake protocol framing)..."
	@$(VERUS) handshake_proofs.rs
	@echo "   ✓ handshake_proofs: 6 verified"

summary:
	@echo "paraxiom-qssh Verus Tier 2: ~20 proofs across 4 files"
	@echo "  transport_proofs.rs — 6 proofs (frame layout, roundtrip, padding)"
	@echo "  kdf_proofs.rs       — 4 proofs (salt, key lengths, determinism)"
	@echo "  mlkem_proofs.rs     — 4 proofs (encaps/decaps, sizes, agreement)"
	@echo "  handshake_proofs.rs — 6 proofs (framing, bounds, version, kex)"

clean:
	@echo "Nothing to clean (Verus proofs are standalone)."
