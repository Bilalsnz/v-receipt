# V-Receipt benchmark results

## Environment

- Device: Infinix X6725B
- Operating system: Android 15
- Runtime: Node.js v26.13.0
- Execution environment: Termux
- Run date: 2026-11-16
- Repetitions: one benchmark invocation per algorithm
- Workload: 24 synthetic traces × 8 events = 192 genuine events
- Verification: 24 clean-log trials and 120 adversarial trials per algorithm

These are measurements from the submitting device. They are not estimates or results from a desktop environment.

## HMAC-SHA256

| Attack | Attempts | Detected | Detection rate |
|---|---:|---:|---:|
| Argument mutation | 24 | 24 | 100.00% |
| Step deletion | 24 | 24 | 100.00% |
| Output spoofing | 24 | 24 | 100.00% |
| Block reordering | 24 | 24 | 100.00% |
| Event injection | 24 | 24 | 100.00% |
| **Overall** | **120** | **120** | **100.00%** |

| Metric | Result |
|---|---:|
| Clean verification trials | 24 |
| False positive rate | 0.00% |
| Mean append latency | 0.6034 ms/step |
| Median append latency | 0.2868 ms/step |
| Detection criterion (100%) | PASS |
| False-positive criterion (0%) | PASS |
| Mean latency criterion (<2 ms) | PASS |

## Ed25519

| Attack | Attempts | Detected | Detection rate |
|---|---:|---:|---:|
| Argument mutation | 24 | 24 | 100.00% |
| Step deletion | 24 | 24 | 100.00% |
| Output spoofing | 24 | 24 | 100.00% |
| Block reordering | 24 | 24 | 100.00% |
| Event injection | 24 | 24 | 100.00% |
| **Overall** | **120** | **120** | **100.00%** |

| Metric | Result |
|---|---:|
| Clean verification trials | 24 |
| False positive rate | 0.00% |
| Mean append latency | 0.6778 ms/step |
| Median append latency | 0.4594 ms/step |
| Detection criterion (100%) | PASS |
| False-positive criterion (0%) | PASS |
| Mean latency criterion (<2 ms) | PASS |

## Comparison

| Metric | HMAC-SHA256 | Ed25519 |
|---|---:|---:|
| Adversarial trials detected | 120/120 | 120/120 |
| Overall detection rate | 100.00% | 100.00% |
| False positive rate | 0.00% | 0.00% |
| Mean append latency | 0.6034 ms/step | 0.6778 ms/step |
| Median append latency | 0.2868 ms/step | 0.4594 ms/step |

In this single observed run, Ed25519 mean append latency was 0.0744 ms/step higher than HMAC-SHA256 (about 12.3% higher relative to HMAC), while both remained below the 2 ms criterion. Both algorithms detected all five tested tampering classes in all 24 trials per class.

## Interpretation and limitations

The results support the limited claim that this implementation detected the five tested forms of record manipulation in this synthetic benchmark, with no clean-log failures observed in 24 trials per algorithm. They do not establish universal tamper detection, production security, or statistical reliability across workloads and devices.

The latency figure is local append latency (canonicalization, hashing, and signing), not end-to-end agent latency or verification latency. Only one benchmark invocation was performed per algorithm; no variance, confidence intervals, or cross-device comparison are available. The benchmark does not test key compromise, malicious event capture, signer compromise, truncation of a valid chain prefix without an external checkpoint, or other out-of-scope threats.

Reproduce from the repository root:

```sh
node benchmark.ts
ALGORITHM=ed25519 node benchmark.ts
```
