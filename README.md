# V-Receipt — VeriAgent Receipts

A lightweight, dependency-free TypeScript prototype for cryptographically chained, tamper-evident records of AI-agent actions, tool outputs, reasoning summaries, and decisions.

**Research track:** Apart Research — AI x Epistemics, Track 2: Trust Infrastructure.

## Research question

What minimal cryptographic layer can make records of agent actions and decisions tamper-evident and independently verifiable, beyond ordinary observability logs?

## What this prototype provides

- Recursive deterministic JSON canonicalization (object keys sorted; array order preserved).
- SHA-256 payload digests and chained block hashes.
- HMAC-SHA256 mode for shared-secret integrity/authentication.
- Ed25519 mode for third-party verification using a public key.
- A verifier that reports the first invalid block index.
- A small adversarial harness covering payload mutation, deletion, output spoofing, reordering, and insertion.

## Requirements

- Node.js **22.18.0 or newer** with built-in TypeScript type stripping.
- No npm dependencies.

Check:

```sh
node --version
```

Run the benchmark:

```sh
node benchmark.ts
```

Run the Ed25519 variant:

```sh
ALGORITHM=ed25519 node benchmark.ts
```

For HMAC, set a fresh secret in your environment rather than using the benchmark's local default:

```sh
export V_RECEIPT_HMAC_SECRET='replace-with-a-long-random-secret'
node benchmark.ts
```

Save a run:

```sh
node benchmark.ts | tee results/benchmark-results.md
```

The benchmark emits Markdown. Run it on the device you intend to report and record the exact device, Android/Termux version, Node.js version, algorithm, and date.

## Minimal API example

```ts
import { AuditChain, generateEd25519Keys } from "./audit-chain.ts";

const keys = generateEd25519Keys();
const writer = new AuditChain({
  algorithm: "Ed25519",
  privateKey: keys.privateKey,
});

writer.append("tool_call", {
  tool: "search",
  arguments: { query: "example" },
});

const receiptLog = writer.getBlocks();

const verification = AuditChain.verify(receiptLog, {
  algorithm: "Ed25519",
  publicKey: keys.publicKey,
});

console.log(verification);
```

The public key can be distributed to auditors. Keep the private key secret. Exported PEM keys are provided by `generateEd25519Keys()`.

## Security model and limitations

1. **Integrity is not truth.** A valid receipt proves that the signed record has not changed relative to the signing key and chain, not that the agent's statement accurately describes reality.
2. **Key compromise matters.** An attacker with the HMAC secret (or Ed25519 private key) can forge records. Ed25519 avoids sharing the signing key with verifiers but does not protect a compromised signer.
3. **Truncation needs an external anchor.** A verifier given only a shortened valid prefix cannot know that later blocks once existed. Publish or externally timestamp signed chain-head checkpoints and expected sequence numbers.
4. **No trusted timestamping.** Timestamps are supplied by the host clock. They are not independent proof of wall-clock time.
5. **Reasoning privacy.** Prefer recording concise reasoning summaries, evidence references, and policy identifiers rather than private chain-of-thought.
6. **Canonicalization scope.** The implementation accepts JSON-compatible values, rejects non-finite numbers and non-plain objects, and preserves array order. It is a prototype, not a formal implementation of RFC 8785/JCS.
7. **Benchmark scope.** The included attacks are controlled mutations of the prototype's exported log. They are not a comprehensive red-team evaluation.

## Repository contents

- `audit-chain.ts`: chain, signing, verification, and framework-neutral wrapper.
- `benchmark.ts`: deterministic synthetic trace and tamper benchmark.
- `research/research-paper.md`: research framing and limitations.
- `results/benchmark-results.md`: reserved for measured output; do not report target values as results.

## Status

Research prototype. Not audited, not production-certified, and not a replacement for secure key management, trusted execution, or external checkpointing.
