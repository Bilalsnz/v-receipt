import { performance } from "node:perf_hooks";
import {
  AuditChain,
  generateEd25519Keys,
  type AuditBlock,
  type AuditOptions,
} from "./audit-chain.ts";

const TRACE_COUNT = 24;
const EVENTS_PER_TRACE = 8;
const USE_ED25519 = process.env.ALGORITHM === "ed25519";

const secret = process.env.V_RECEIPT_HMAC_SECRET ?? "local-benchmark-only-change-me";
const keys = USE_ED25519 ? generateEd25519Keys() : undefined;

const signingOptions: AuditOptions = USE_ED25519
  ? { algorithm: "Ed25519", privateKey: keys!.privateKey }
  : { algorithm: "HMAC-SHA256", secret };

const verificationOptions: AuditOptions = USE_ED25519
  ? { algorithm: "Ed25519", publicKey: keys!.publicKey }
  : { algorithm: "HMAC-SHA256", secret };

const attackNames = [
  "Argument mutation",
  "Step deletion",
  "Output spoofing",
  "Block reordering",
  "Event injection",
];

const stats = attackNames.map((name) => ({ name, attempts: 0, detected: 0 }));
const latencies: number[] = [];
let cleanTrials = 0;
let falsePositives = 0;
let totalEvents = 0;

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function makeTrace(traceId: number): AuditBlock[] {
  const chain = new AuditChain(signingOptions);
  const events = [
    ["tool_call", { tool: "filesystem.read", arguments: { path: `/workspace/file-${traceId}.txt`, encoding: "utf8" } }],
    ["tool_output", { tool: "filesystem.read", output: { content: `file-content-${traceId}`, bytes: 128 }, success: true }],
    ["tool_call", { tool: "api.search", arguments: { query: `research-${traceId}`, limit: 10 } }],
    ["tool_output", { tool: "api.search", output: { results: [`result-${traceId}-1`, `result-${traceId}-2`] }, success: true }],
    ["llm_reasoning", { summary: "Evaluated retrieved evidence", evidenceCount: 2, confidence: 0.92 }],
    ["tool_call", { tool: "filesystem.write", arguments: { path: `/workspace/output-${traceId}.txt`, content: "verified result" } }],
    ["tool_output", { tool: "filesystem.write", output: { success: true, bytesWritten: 15 }, success: true }],
    ["final_decision", { decision: "approved", traceId, evidenceCount: 2, confidence: 0.92 }],
  ] as const;

  for (const [event, payload] of events) {
    const start = performance.now();
    chain.append(event, payload);
    latencies.push(performance.now() - start);
    totalEvents++;
  }
  return chain.getBlocks();
}

function tamper(type: number, source: AuditBlock[]): AuditBlock[] {
  const blocks = clone(source);
  switch (type) {
    case 0:
      blocks[0].payload = {
        tool: "filesystem.read",
        arguments: { path: "/etc/passwd", encoding: "utf8" },
      };
      break;
    case 1:
      blocks.splice(3, 1);
      break;
    case 2:
      blocks[1].payload = {
        tool: "filesystem.read",
        output: { content: "ATTACKER-CONTROLLED DATA", bytes: 999999 },
        success: true,
      };
      break;
    case 3: {
      const tmp = blocks[2];
      blocks[2] = blocks[5];
      blocks[5] = tmp;
      break;
    }
    case 4: {
      const forged = clone(blocks[2]);
      forged.index = 3;
      forged.event = "final_decision";
      forged.payload = { decision: "unauthorized", injected: true };
      blocks.splice(3, 0, forged);
      break;
    }
    default:
      throw new Error("Unknown attack");
  }
  return blocks;
}

function main(): void {
  for (let trace = 0; trace < TRACE_COUNT; trace++) {
    const original = makeTrace(trace);
    cleanTrials++;
    if (!AuditChain.verify(clone(original), verificationOptions).valid) falsePositives++;

    for (let attack = 0; attack < stats.length; attack++) {
      stats[attack].attempts++;
      const result = AuditChain.verify(tamper(attack, original), verificationOptions);
      if (!result.valid) stats[attack].detected++;
    }
  }

  const attempts = stats.reduce((n, x) => n + x.attempts, 0);
  const detected = stats.reduce((n, x) => n + x.detected, 0);
  const detectionRate = attempts ? (detected / attempts) * 100 : 0;
  const fpRate = cleanTrials ? (falsePositives / cleanTrials) * 100 : 0;
  const sorted = [...latencies].sort((a, b) => a - b);
  const average = latencies.reduce((a, b) => a + b, 0) / latencies.length;
  const median = sorted.length % 2
    ? sorted[Math.floor(sorted.length / 2)]
    : (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2;

  console.log("# V-Receipt benchmark results");
  console.log("");
  console.log(`- Algorithm: ${USE_ED25519 ? "Ed25519" : "HMAC-SHA256"}`);
  console.log(`- Traces: ${TRACE_COUNT}`);
  console.log(`- Events per trace: ${EVENTS_PER_TRACE}`);
  console.log(`- Genuine events: ${totalEvents}`);
  console.log(`- Clean verification trials: ${cleanTrials}`);
  console.log(`- Adversarial trials: ${attempts}`);
  console.log("");
  console.log("| Attack | Attempts | Detected | Detection rate |");
  console.log("|---|---:|---:|---:|");
  for (const item of stats) {
    const rate = item.attempts ? (item.detected / item.attempts) * 100 : 0;
    console.log(`| ${item.name} | ${item.attempts} | ${item.detected} | ${rate.toFixed(2)}% |`);
  }
  console.log("");
  console.log("| Metric | Result |");
  console.log("|---|---:|");
  console.log(`| Overall tamper detection rate | ${detectionRate.toFixed(2)}% |`);
  console.log(`| False positive rate | ${fpRate.toFixed(2)}% |`);
  console.log(`| Mean append latency | ${average.toFixed(4)} ms/step |`);
  console.log(`| Median append latency | ${median.toFixed(4)} ms/step |`);
  console.log("");
  console.log("| Acceptance criterion | Result |");
  console.log("|---|---|");
  console.log(`| Detection rate = 100% | ${detectionRate === 100 ? "PASS" : "FAIL"} |`);
  console.log(`| False positive rate = 0% | ${fpRate === 0 ? "PASS" : "FAIL"} |`);
  console.log(`| Mean append latency < 2 ms | ${average < 2 ? "PASS" : "FAIL"} |`);
  console.log("");
  console.log("> Latency is local append latency (canonicalization, hashing, signing) on this machine. It is not end-to-end agent latency. Run on the target device and record its model, OS, and Node.js version.");
}

main();
