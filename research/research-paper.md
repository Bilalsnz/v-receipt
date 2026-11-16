# V-Receipt: A Minimal Cryptographic Receipt Layer for Auditable AI-Agent Execution

**Track:** Apart Research AI x Epistemics — Track 2: Trust Infrastructure  
**Status:** Prototype and experimental plan

## Abstract

AI-agent observability systems commonly record events such as tool invocations, tool outputs, and decisions. A conventional log, however, may be editable by the process or infrastructure that produced it. This project investigates whether a small cryptographic receipt layer can make such records tamper-evident and independently verifiable. V-Receipt is a dependency-free TypeScript prototype that canonicalizes JSON payloads, hashes each payload, chains records using SHA-256, and signs each block using either HMAC-SHA256 or Ed25519. Its verifier checks the chain sequentially and reports the first failing index. A synthetic benchmark exercises five classes of log manipulation. The prototype demonstrates a concrete integrity mechanism, while its evaluation is intentionally scoped: it does not establish that logged events are truthful, that the signing host is uncompromised, or that a valid prefix is complete without an external checkpoint.

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

### 3.2 Results

**Results must be populated from an actual run on the submitting device.** The repository's `benchmark.ts` prints a Markdown table. Do not claim 100% detection, 0% false positives, or sub-2ms latency until the run has produced those measurements.

Record at minimum:

- Device model and Android/Termux version.
- Node.js version.
- Signature algorithm.
- Run date and number of repetitions.
- Attack counts and detections by attack type.
- Clean verification failures.
- Mean and median append latency.

The current harness measures local append latency (canonicalization, hashing, and signing), not end-to-end agent latency or verifier latency. A stronger study should repeat runs, report variance or percentiles, and compare HMAC with Ed25519 on the same device.

### 3.3 Threats to validity

The attack set is intentionally small and deterministic. It tests common structural and payload tampering but not key theft, malicious signer behavior, compromised runtime instrumentation, filesystem rollback, concurrent writers, denial of service, or attacks against the host clock. Synthetic traces may not represent production agent workloads. Performance measurements are hardware- and runtime-dependent.

## 4. Governance and real-world impact

A receipt chain can make exported execution records easier to exchange across organizational boundaries. A platform could emit receipts while an external auditor verifies them using a public key, reducing reliance on access to the platform's signing secret. This could support incident review, tool-use accountability, policy compliance evidence, and post-deployment audits.

The receipt layer complements rather than replaces observability. It does not prove that a tool actually executed as described, that an output came from the claimed external service, or that a decision was justified. Stronger deployments would combine receipts with authenticated tool gateways, key isolation, independently operated checkpoints, trusted timestamping, and retention controls.

## 5. Conclusion

V-Receipt explores a small, implementable trust primitive for agent observability: canonicalized, hash-chained, cryptographically signed execution receipts. Ed25519 provides a practical route to third-party verification without sharing the signing secret. The prototype and benchmark provide a reproducible starting point for evaluating integrity and overhead. The central limitation remains that cryptographic integrity is not equivalent to factual truth or completeness; external anchoring and trustworthy event capture are necessary for stronger audit claims.

## References and related work to verify before submission

The final submission should cite and compare relevant standards and systems, including:

- RFC 8785, JSON Canonicalization Scheme (JCS).
- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA).
- W3C PROV data model and provenance concepts.
- OpenTelemetry logs, traces, and event conventions.
- Relevant AI-agent observability and audit-log systems.

Add precise citations, versions, and a clear comparison table after checking the primary sources. Do not imply that this prototype is the first hash-chain or signed-log system; state the specific gap and contribution supported by the literature review.
