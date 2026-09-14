# Design note: binding served outputs to the audited model

Matthew K. Ngoy. Mentor: Boyang Li. Kean University, Fall 2026.

This note covers the model-substitution attack and the question it raises:
how do you prove that the output a node served came from the model it
committed on-chain? It is the "short design write-up on binding served
outputs to the audited model" listed in the proposal.

## The gap in the prototype

In `hadagent/src/podl_chain/pdl.py`, `verify_podl_llm_eval` takes the
endpoint URL out of the miner's own proof record and POSTs the eval
prompts there. The record also carries `artifact_hash`, meant to identify
the committed weights. Nothing in the code checks that the model answering
at that endpoint is the model the hash names. The verifier trusts whatever
responds.

So a node can commit model A, answer audits from A, and serve model B to
real users. Consensus cannot tell, because score reproduction is all it
checks.

## The attack (two forms)

**Lookup table (no model).** The evalset is public and its hash is in the
record. The node precomputes answers once and serves them from a
dictionary, passing the audit with no model running. `runners/model_binding.py`
sketches this today but grades the table against the file it was built
from, so it is not yet a real demonstration.

**Two-model swap (the safety-relevant form).** The node commits an aligned
model and serves an unaligned one.
- Committed / audited: Llama-3.2-3B Instruct (aligned). Answers the audit path.
- Served: an uncensored variant, or the same model with the safety system
  prompt stripped. Answers real user requests.
Both score about the same on MMLU, so the audit passes. The served model
complies with harmful requests the committed one refuses. Jailbreak prompts
and a HarmBench subset are used here to measure the compliance gap between
the two models, on a node that passes 100% of audits.

## Can this be closed by "cryptographically proving" the model?

There is no cheap, fully sound way today to prove "this output came from
these exact weights." The options, strongest to cheapest:

1. **zkML (zero-knowledge proof of inference).** Prove y = f(x, W) with
   commit(W) equal to the on-chain hash, revealing nothing else. The real
   cryptographic answer (tools such as EZKL). Cost is the blocker: proving
   a full forward pass of a 3B-7B transformer is currently far too
   expensive for serving latency. The cost itself is a finding, tied to the
   verifier's-dilemma and proof-of-learning cost results already cited.

2. **TEE remote attestation.** Run inference inside an enclave (Intel TDX,
   NVIDIA H100 confidential computing). The hardware attests that it loaded
   hash h and produced y. Deployable today. It is a hardware root of trust,
   not pure cryptography: trusts the chip vendor, and side channels exist.

3. **Weight commitment plus challenge-opening.** Commit a Merkle root over
   the weights; on audit, reveal random weight slices with Merkle proofs.
   Proves the node possesses the committed weights. Does not prove it used
   them for any given output.

4. **Fingerprinting / rotating challenges.** Secret probe set the committed
   model answers in known ways; a substituted model fails the probes.
   Detection, not proof. Probabilistic and evadable if the adversary can
   separate probe traffic from real traffic. This is the "hidden rotating
   challenges" defense in the proposal.

## What this project builds vs. writes up

- **Build:** the fingerprint / rotating-challenge detector (rung 4). Cheap,
  real, measurable. Report substitution success rate before and after, as a
  function of how well the adversary separates probe traffic from real
  traffic. Also add the safety judge to the verification path so it inspects
  the served output, not just the score, and measure harmful-compliance
  before and after.
- **Write up (design only):** the cryptographic binding (rungs 1-3), with
  honest cost characterizations. zkML is sound but too expensive at serving
  latency; TEE attestation is the deployable middle; commitment-opening
  proves possession but not use.

Honest limitation to state plainly: the safety judge catches unsafe
outputs, fingerprinting catches substitution probabilistically, and true
cryptographic binding needs zkML or a TEE whose cost is the open problem
this line of work runs into.
