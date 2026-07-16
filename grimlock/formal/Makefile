# Machine-check the Grimlock core lemmas (Coq) and protocol models (Tamarin).
# Requires coqc >= 8.16 and, for the protocol proofs, tamarin-prover.
COQC ?= coqc
COQTOP ?= coqtop
TAMARIN ?= tamarin-prover

.PHONY: all axioms tamarin clean

all: Grimlock.vo

# Prove the protocol models: the resumption handshake (mutual agreement, relay
# resistance, RS secrecy) and the gate EKM-binding (relay resistance of quotes).
tamarin: resumption.spthy gate.spthy
	$(TAMARIN) --prove resumption.spthy 2>&1 | grep -E 'verified|falsified'
	$(TAMARIN) --prove gate.spthy 2>&1 | grep -E 'verified|falsified'

Grimlock.vo: Grimlock.v
	$(COQC) $<

# Confirm every headline theorem is axiom-free (prints "Closed under the global context").
axioms: Grimlock.v
	@{ cat Grimlock.v; \
	   printf '\nPrint Assumptions transcript_injective.\n'; \
	   printf 'Print Assumptions covered_monotone.\n'; \
	   printf 'Print Assumptions covered_attenuation.\n'; \
	   printf 'Print Assumptions no_grant_denied.\n'; \
	   printf 'Print Assumptions covered_refine.\n'; } \
	 | $(COQTOP) -q 2>&1 | grep -iE 'closed under|axiom'

clean:
	rm -f *.vo *.vok *.vos *.glob .*.aux
