# V-Receipt: A Minimal Cryptographic Receipt Layer for Auditable AI-Agent Execution

**Track:** Apart Research AI x Epistemics — Track 2: Trust Infrastructure  
**Status:** Prototype evaluated in a single-device synthetic benchmark

## Abstract

AI-agent observability systems commonly record events such as tool invocations, tool outputs, and decisions. A conventional log, however, may be editable by the process or infrastructure that produced it. This project investigates whether a small cryptographic receipt layer can make such records tamper-evident and independently verifiable. V-Receipt is a dependency-free TypeScript prototype that canonicalizes JSON payloads, hashes each payload, chains records using SHA-256, and signs each block using either HMAC-SHA256 or Ed25519. Its verifier checks the chain sequentially and reports the first failing index. On an Infinix X6725B running Android 15 and Node.js v26.13.0, a synthetic benchmark observed 100% detection across 120 adversarial trials and 0% false positives across 24 clean trials for each algorithm. Mean local append latency was 0.6034 ms/step for HMAC-SHA256 and 0.6778 ms/step for Ed25519. These are single-run results on one device, not evidence of universal security or production performance. The prototype does not establish that logged events are truthful, that the signing host is uncompromised, or that a valid prefix is complete without an external checkpoint.

## 1. Problem statement

Agent observability answers questions such as which tool was called, what output was returned, and what decision was recorded. These records become evidence in debugging, incident response, governance, and accountability workflows. If the same system that emits the log can silently alter or rewrite it, downstream auditors must trust the logging infrastructure rather than verify the record itself.

The research question is:

**What minimal tamper-evident layer is missing from today's AI observability standards so that records of what agents did and agreed can be audited and trusted?**

We investigate a narrow candidate primitive: a signed, append-ordered receipt chain over canonicalized event payloads.

## 2. Methodology and architecture

### 2.1 Event model

The prototype supports four event classes:

- `tool_call`: tool name and submitted arguments.
- `tool_output`: returned output or error status.
- `llm_reasoning`: a concise reasoning summary or evidence references.
- `final_decision`: the recorded outcome.

Sensitive internal reasoning should not be indiscriminately captured. An auditable summary, evidence identifiers, and policy references are often more appropriate.

### 2.2 Canonicalization

Before hashing, JSON objects are recursively normalized with lexicographically sorted keys. Array order is preserved. Non-finite numbers, undefined values, circular references, and non-plain objects are rejected. This ensures that semantically identical supported JSON objects with different insertion orders produce the same serialized representation.

This is a deliberately small canonicalization profile; it is not claimed to be a complete RFC 8785/JCS implementation.

### 2.3 Receipt construction

For event i, the implementation computes:

- payloadHash_i = SHA-256(canonicalJSON(payload_i))
- blockHash_i = SHA-256(canonicalJSON(index, timestamp, event, payloadHash_i, previous block hash, previous signature hash, algorithm))
- signature_i = Sign_key(blockHash_i)

The next receipt commits to both the previous block hash and the hash of the previous signature. The genesis links are fixed constants.

### 2.4 Signature modes

**HMAC-SHA256** uses a shared secret. It can authenticate records among parties that share that secret, but every verifier holding it can also forge records.

**Ed25519** uses a private signing key and a public verification key. An auditor can verify receipts without receiving the private key. This improves separation between the agent signer and independent verifier.

### 2.5 Verification

The verifier walks blocks in order and checks indices, previous-block links, previous-signature links, event type, algorithm, payload digest, block digest, and signature. It returns the first failing index and a diagnostic category.

## 3. Empirical evaluation

### 3.1 Experimental design

The benchmark generates 24 synthetic traces with eight events each (192 genuine events). Each trace is verified unchanged and subjected to five attacks:

1. Argument mutation.
2. Deletion of an intermediate step.
3. Tool-output spoofing.
4. Reordering of existing blocks.
5. Injection of a fabricated event.

This creates 120 adversarial trials and 24 clean-log verification trials per algorithm run. The harness reports attack-specific and aggregate detection rates, clean-log false-positive rate, and local append latency.

The benchmark was run once per algorithm on an Infinix X6725B running Android 15 in Termux with Node.js v26.13.0, on 2026-11-16.

### 3.2 Results

| Metric | HMAC-SHA256 | Ed25519 |
|---|---:|---:|
| Genuine events generated | 192 | 192 |
| Clean verification trials | 24 | 24 |
| Adversarial trials | 120 | 120 |
| Argument mutation detected | 24/24 (100%) | 24/24 (100%) |
| Step deletion detected | 24/24 (100%) | 24/24 (100%) |
| Output spoofing detected | 24/24 (100%) | 24/24 (100%) |
| Block reordering detected | 24/24 (100%) | 24/24 (100%) |
| Event injection detected | 24/24 (100%) | 24/24 (100%) |
| Overall tamper detection | 120/120 (100%) | 120/120 (100%) |
| False positive rate | 0.00% | 0.00% |
| Mean append latency | 0.6034 ms/step | 0.6778 ms/step |
| Median append latency | 0.2868 ms/step | 0.4594 ms/step |

All three benchmark acceptance criteria passed for both algorithms: 100% detection in the tested adversarial trials, 0% false positives in the clean trials, and mean append latency below 2 ms. In this run, Ed25519 mean append latency was 0.0744 ms/step higher than HMAC-SHA256 (approximately 12.3% higher relative to HMAC). Both remained below the stated threshold.

These results support only a bounded empirical statement: under the harness's five synthetic tampering operations, this implementation detected all manipulated traces in the observed trials, and no clean trace was rejected. A 0% observed false-positive rate over 24 trials is not proof that the true rate is zero. Similarly, 100% observed detection over 120 trials is not proof against untested attacks.

The harness measures local append latency (canonicalization, hashing, and signing), not end-to-end agent latency or verifier latency. Only one invocation per algorithm was performed. No variance, confidence intervals, repeated-run stability, or cross-device comparison is available.

### 3.3 Threats to validity

The attack set is intentionally small and deterministic. It tests common structural and payload tampering but not key theft, malicious signer behavior, compromised runtime instrumentation, filesystem rollback, concurrent writers, denial of service, or attacks against the host clock. Synthetic traces may not represent production agent workloads. Performance measurements are hardware- and runtime-dependent. The single-run design limits conclusions about latency and error rates.

A further limitation is chain truncation: if an auditor receives only a shortened but otherwise valid prefix, the chain alone cannot prove that later records existed. An independently retained chain-head checkpoint, sequence commitment, or external anchoring mechanism is needed to detect this form of omission.

## 4. Governance and real-world impact

A receipt chain can make exported execution records easier to exchange across organizational boundaries. A platform could emit receipts while an external auditor verifies them using a public key, reducing reliance on access to the platform's signing secret. This could support incident review, tool-use accountability, policy compliance evidence, and post-deployment audits.

The receipt layer complements rather than replaces observability. It does not prove that a tool actually executed as described, that an output came from the claimed external service, or that a decision was justified. Stronger deployments would combine receipts with authenticated tool gateways, key isolation, independently operated checkpoints, trusted timestamping, and retention controls.

## 5. Conclusion

V-Receipt explores a small, implementable trust primitive for agent observability: canonicalized, hash-chained, cryptographically signed execution receipts. In a single-device synthetic benchmark, both HMAC-SHA256 and Ed25519 detected all 120 tested manipulations per algorithm, with no false positives among 24 clean trials. Mean local append latency was below 1 ms per step for both modes on the tested device. Ed25519 provides a practical route to third-party verification without sharing the signing secret, at a modestly higher observed append cost in this run.

The findings are preliminary. They demonstrate feasibility under a bounded test harness, not comprehensive security. Cryptographic integrity is not equivalent to factual truth or completeness; external anchoring, trustworthy event capture, key protection, and broader adversarial evaluation are necessary for stronger audit claims.

## References and related work to verify before submission

The final submission should cite and compare relevant standards and systems, including:

- RFC 8785, JSON Canonicalization Scheme (JCS).
- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA).
- W3C PROV data model and provenance concepts.
- OpenTelemetry logs, traces, and event conventions.
- Relevant AI-agent observability and audit-log systems.

Add precise citations, versions, and a clear comparison table after checking the primary sources. Do not imply that this prototype is the first hash-chain or signed-log system; state the specific gap and contribution supported by the literature review.
