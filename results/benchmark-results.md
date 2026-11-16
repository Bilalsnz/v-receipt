# V-Receipt benchmark results

## Environment

- Device: Infinix X6725B
- Operating system: Android 15
- Runtime: Node.js v26.13.0
- Execution environment: Termux
- Run date: 2026-11-16
- Repetitions: five benchmark invocations per algorithm (repeatability experiment)
- Workload: 24 synthetic traces × 8 events = 192 genuine events
- Verification: 24 clean-log trials and 120 adversarial trials per algorithm

These are measurements from the submitting device. They are not estimates or results from a desktop environment.

## HMAC-SHA256 — initial baseline run

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

## Ed25519 — initial baseline run

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

## Initial baseline comparison

| Metric | HMAC-SHA256 | Ed25519 |
|---|---:|---:|
| Adversarial trials detected | 120/120 | 120/120 |
| Overall detection rate | 100.00% | 100.00% |
| False positive rate | 0.00% | 0.00% |
| Mean append latency | 0.6034 ms/step | 0.6778 ms/step |
| Median append latency | 0.2868 ms/step | 0.4594 ms/step |

In this single observed run, Ed25519 mean append latency was 0.0744 ms/step higher than HMAC-SHA256 (about 12.3% higher relative to HMAC), while both remained below the 2 ms criterion. Both algorithms detected all five tested tampering classes in all 24 trials per class.

## Five-run repeatability experiment

The benchmark was repeated five times per algorithm on the same device and runtime. Each invocation used 24 traces, 192 genuine events, 24 clean-log trials, and 120 adversarial trials. Across five runs, each algorithm therefore had 600 adversarial trials and 120 clean-log trials.

| Metric across five runs | HMAC-SHA256 | Ed25519 |
|---|---:|---:|
| Adversarial detections | 600/600 (100.00%) | 600/600 (100.00%) |
| Clean-log false positives | 0/120 (0.00%) | 0/120 (0.00%) |
| Mean of per-run mean append latency | 0.4886 ms/step | 0.6497 ms/step |
| Sample SD of per-run mean append latency | 0.0898 ms/step | 0.0454 ms/step |
| Range of per-run mean append latency | 0.4109–0.6129 ms/step | 0.6021–0.7069 ms/step |
| Mean of per-run median append latency | 0.3049 ms/step | 0.5000 ms/step |

Every one of the five runs for both algorithms detected all 24/24 instances of each of the five attack types, reported 0% false positives, and passed the <2 ms mean append-latency criterion.

Across these repeated runs, Ed25519's average per-run mean append latency was approximately 33.0% higher than HMAC-SHA256's. This is a descriptive comparison from five runs on one device, not a general performance guarantee. The standard deviations describe variation between these five invocation-level measurements; they are not confidence intervals.

## Interpretation and limitations

The results support the limited claim that this implementation detected the five tested forms of record manipulation in this synthetic benchmark, with no clean-log failures observed in 24 trials per algorithm. They do not establish universal tamper detection, production security, or statistical reliability across workloads and devices.

The latency figure is local append latency (canonicalization, hashing, and signing), not end-to-end agent latency or verification latency. Five invocations per algorithm were performed on the same device. The reported sample standard deviations describe only between-run variation in this small repeatability check; they are not confidence intervals, and no cross-device comparison is available. The benchmark does not test key compromise, malicious event capture, signer compromise, truncation of a valid chain prefix without an external checkpoint, or other out-of-scope threats.

Reproduce from the repository root:

```sh
node benchmark.ts
ALGORITHM=ed25519 node benchmark.ts
```
