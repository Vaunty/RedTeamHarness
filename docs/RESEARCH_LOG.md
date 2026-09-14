# Research log: Red-teaming Proof-of-Inference in HadAgent

Matthew K. Ngoy. Mentor: Boyang Li. Kean University, Fall 2026.

This is the tracking document requested at the September 4 kickoff meeting: meeting notes, the planned timeline, and a progress entry every two weeks. If a two-week period has no progress, that will be stated here explicitly.

## Timeline (from the proposal)

| Weeks | Dates | Primary deliverable |
|---|---|---|
| 1-2 | Sep 1 - Sep 11 | Read HadAgent closely; threat-model extension; scaffold harness and judge |
| 3-4 | Sep 14 - Sep 25 | Property-based test suite; reproduce the tuple bug before and after the fix |
| 5-6 | Sep 28 - Oct 9 | Reproducibility-is-not-safety demonstration; lookup-table / model-swap audit evasion |
| 7-8 | Oct 12 - Oct 23 | Determinism attack: score divergence across quantization, threads, library versions |
| 9-10 | Oct 26 - Nov 6 | Trust-then-betray on the minimal two-tier serving harness |
| 11-12 | Nov 9 - Nov 20 | Defenses: safety judge in the verification path; stretch: real-request auditing |
| 13-14 | Nov 23 - Dec 4 | Paper draft, reproducible artifact, poster |
| 15-16 | Dec 7 - Dec 21 | Final report and advisor sign-off |

## Meeting notes

### 2026-09-04, kickoff (Zoom, group)

Led by Boyang Li. Attendees included students from several universities.

Topics discussed:
- Four research directions: (1) replacing Bitcoin's hash algorithm with deep learning so mining compute goes to useful work such as LLM inference; (2) machine unlearning in LLMs and diffusion models; (3) LLM safety and hallucination, both attack and defense; (4) agentic AI reliability and security.
- I expressed interest in direction (1). Prior work in that direction (the HadAgent paper on inference agents) is published and the project is described as nearing completion.
- Expectations: pick a topic that can grow into a coherent line of work rather than a one-off; aim to submit a paper by the end of this semester or early next; bi-weekly updates as a baseline; three weeks without an update is flagged.
- Each student keeps a document with meeting notes, timeline, and bi-weekly progress. No progress in a two-week window must be stated explicitly.
- Group meetings will replace most one-on-ones.

Action items for me:
- Maintain this document.
- Select a direction and send write-ups to Boyang.

### 2026-09-10 (Slack, direct message)

I told Boyang I would send my write-ups and direction for the blockchain research and asked whether email, DM, or a channel is preferred. He replied "Great!". Boyang's group message the same week reminded everyone that week two should end with a chosen direction and a start on related papers or tech blogs.

## Progress

### 2026-09-04 to 2026-09-14 (weeks 1-2)

Done:
- Read the HadAgent paper, slide deck, and the prototype source and git history.
- Confirmed the prototype contains the consensus core only. The anomaly detector, trust manager, two-tier serving, and heartbeat monitor from the paper are not in the code.
- Confirmed the tuple validation bug in the repo history: introduced in `1a8d490` (2026-03-31), fixed in `a4ec9da` (2026-04-13). Reproduced it in `runners/validation_fuzzing.py`.
- Found that `pdl.py` verifies proofs by POSTing to the endpoint URL from the miner's own record, and that the evalset file `block.py` references is not in the repo.
- Wrote the proposal (`Red_Team_HadAgent_POI_Proposal.pdf`) with threat model, three attacks, defenses, and timeline.
- Built `core/poi/` (records, blocks, anomaly detector with exact and tolerance modes, trust manager, two-tier server, simulated node) and five attack runners. All runners execute; unit tests pass.

Not done / caveats:
- No real model inference has run. Every runner currently uses simulated or hardcoded scores. README and THREAT_MODEL label which numbers are placeholders.
- The validation fuzzer uses hand-written cases, not Hypothesis strategies yet.

### 2026-09-14 to 2026-09-25 (weeks 3-4)

Planned:
- Measure real score divergence: Llama-3.2-3B through llama.cpp at two quantizations.
- Run a HarmBench subset through the safety judge for a measured reproducibility result.
- Move the fuzzer to Hypothesis and pin it against the buggy commit.

Progress:
- Wrote `docs/DESIGN_model_binding.md`: the model-substitution attack (commit an
  aligned model, serve an unaligned one, pass audits from the aligned one) and
  the ladder for binding a served output to the committed model (zkML, TEE
  attestation, weight-commitment opening, fingerprinting). Plan is to build the
  fingerprint / rotating-challenge detector and write up the cryptographic
  binding as design, per the proposal's stretch deliverable.
- Next concrete step: two GGUF models on separate llama.cpp ports and an
  adversarial node that forwards audit traffic to one and real traffic to the
  other, then measure the harmful-compliance gap on a HarmBench subset.
