# Benchmark results

**Not yet measured.** This file is intentionally a placeholder until the benchmark is run on the target device.

Run from the repository root:

```sh
node benchmark.ts | tee results/benchmark-results.md
```

For Ed25519:

```sh
ALGORITHM=ed25519 node benchmark.ts | tee results/benchmark-results-ed25519.md
```

Record device model, Android/Termux version, Node.js version, algorithm, date, and repeat count alongside the output. Do not replace this notice with target or expected values; report only observed measurements.
