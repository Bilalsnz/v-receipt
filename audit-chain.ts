import {
  createHash,
  createHmac,
  generateKeyPairSync,
  sign,
  verify,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";

export type AuditEvent =
  | "tool_call"
  | "tool_output"
  | "llm_reasoning"
  | "final_decision";

export type SignatureAlgorithm = "HMAC-SHA256" | "Ed25519";
export type JSONValue =
  | null | boolean | number | string
  | JSONValue[]
  | { [key: string]: JSONValue };

export interface AuditBlock {
  index: number;
  timestamp: string;
  event: AuditEvent;
  payload: JSONValue;
  payloadHash: string;
  prevHash: string;
  prevSignatureHash: string;
  hash: string;
  algorithm: SignatureAlgorithm;
  signature: string;
}

export interface VerificationResult {
  valid: boolean;
  verifiedBlocks: number;
  totalBlocks: number;
  failedIndex: number | null;
  error: string | null;
}

export interface AuditOptions {
  algorithm?: SignatureAlgorithm;
  secret?: string;
  privateKey?: KeyObject;
  publicKey?: KeyObject;
}

const GENESIS = "0".repeat(64);
const EVENTS = new Set<AuditEvent>([
  "tool_call", "tool_output", "llm_reasoning", "final_decision",
]);

/** Recursively sort object keys; preserve array order; reject non-JSON values. */
export function canonicalize(value: unknown): string {
  const normalize = (input: unknown, ancestors: Set<object>): JSONValue => {
    if (input === null || typeof input === "string" || typeof input === "boolean") {
      return input;
    }
    if (typeof input === "number") {
      if (!Number.isFinite(input)) throw new Error("Non-finite number is not valid JSON");
      return input;
    }
    if (Array.isArray(input)) {
      if (ancestors.has(input)) throw new Error("Circular JSON value");
      const next = new Set(ancestors);
      next.add(input);
      return Array.from(input, (item) => normalize(item, next));
    }
    if (typeof input === "object") {
      if (ancestors.has(input)) throw new Error("Circular JSON value");
      const proto = Object.getPrototypeOf(input);
      if (proto !== Object.prototype && proto !== null) {
        throw new Error("Only plain JSON objects are supported");
      }
      const next = new Set(ancestors);
      next.add(input);
      const output: Record<string, JSONValue> = {};
      for (const key of Object.keys(input).sort()) {
        const item = (input as Record<string, unknown>)[key];
        if (item === undefined) throw new Error(`Undefined at property: ${key}`);
        output[key] = normalize(item, next);
      }
      return output;
    }
    throw new Error(`Unsupported JSON value: ${typeof input}`);
  };
  return JSON.stringify(normalize(value, new Set()));
}

export function sha256(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

function signatureHash(signature: string): string {
  return sha256(signature);
}

function blockHash(block: Omit<AuditBlock, "hash" | "signature">): string {
  // Payload bytes are committed through payloadHash, not duplicated here.
  return sha256(canonicalize({
    index: block.index,
    timestamp: block.timestamp,
    event: block.event,
    payloadHash: block.payloadHash,
    prevHash: block.prevHash,
    prevSignatureHash: block.prevSignatureHash,
    algorithm: block.algorithm,
  }));
}

export function generateEd25519Keys(): {
  privateKey: KeyObject;
  publicKey: KeyObject;
  privateKeyPEM: string;
  publicKeyPEM: string;
} {
  const pair = generateKeyPairSync("ed25519");
  return {
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    privateKeyPEM: pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    publicKeyPEM: pair.publicKey.export({ type: "spki", format: "pem" }) as string,
  };
}

function signHash(hash: string, options: AuditOptions): string {
  const data = Buffer.from(hash, "hex");
  if (options.algorithm === "Ed25519") {
    if (!options.privateKey) throw new Error("Ed25519 signing requires privateKey");
    return sign(null, data, options.privateKey).toString("hex");
  }
  if (!options.secret) throw new Error("HMAC-SHA256 requires secret");
  return createHmac("sha256", options.secret).update(data).digest("hex");
}

function checkSignature(hash: string, signature: string, options: AuditOptions): boolean {
  const data = Buffer.from(hash, "hex");
  try {
    if (options.algorithm === "Ed25519") {
      if (!options.publicKey) throw new Error("Ed25519 verification requires publicKey");
      return verify(null, data, options.publicKey, Buffer.from(signature, "hex"));
    }
    if (!options.secret) throw new Error("HMAC-SHA256 verification requires secret");
    const expected = createHmac("sha256", options.secret).update(data).digest();
    const actual = Buffer.from(signature, "hex");
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch (error) {
    if (error instanceof Error && error.message.includes("requires")) throw error;
    return false;
  }
}

export class AuditChain {
  private readonly blocks: AuditBlock[] = [];
  private readonly options: AuditOptions & { algorithm: SignatureAlgorithm };

  constructor(options: AuditOptions) {
    const algorithm = options.algorithm ?? "HMAC-SHA256";
    this.options = { ...options, algorithm };
    if (algorithm === "Ed25519" && !options.privateKey) {
      throw new Error("Ed25519 requires privateKey");
    }
    if (algorithm === "HMAC-SHA256" && !options.secret) {
      throw new Error("HMAC-SHA256 requires secret");
    }
  }

  append(event: AuditEvent, payload: JSONValue): AuditBlock {
    if (!EVENTS.has(event)) throw new Error(`Invalid audit event: ${event}`);
    const safePayload = JSON.parse(canonicalize(payload)) as JSONValue;
    const previous = this.blocks[this.blocks.length - 1];
    const unsigned: Omit<AuditBlock, "hash" | "signature"> = {
      index: this.blocks.length,
      timestamp: new Date().toISOString(),
      event,
      payload: safePayload,
      payloadHash: sha256(canonicalize(safePayload)),
      prevHash: previous?.hash ?? GENESIS,
      prevSignatureHash: previous ? signatureHash(previous.signature) : GENESIS,
      algorithm: this.options.algorithm,
    };
    const hash = blockHash(unsigned);
    const block: AuditBlock = { ...unsigned, hash, signature: signHash(hash, this.options) };
    this.blocks.push(block);
    return JSON.parse(JSON.stringify(block)) as AuditBlock;
  }

  getBlocks(): AuditBlock[] {
    return JSON.parse(JSON.stringify(this.blocks)) as AuditBlock[];
  }

  get length(): number {
    return this.blocks.length;
  }

  exportJSON(): string {
    return JSON.stringify(this.blocks, null, 2);
  }

  static verify(blocks: AuditBlock[], options: AuditOptions): VerificationResult {
    const fail = (index: number, error: string): VerificationResult => ({
      valid: false,
      verifiedBlocks: index,
      totalBlocks: blocks.length,
      failedIndex: index,
      error,
    });
    const algorithm = options.algorithm ?? "HMAC-SHA256";
    let previousHash = GENESIS;
    let previousSignatureHash = GENESIS;

    for (let i = 0; i < blocks.length; i++) {
      const block = blocks[i];
      if (!block || typeof block !== "object") return fail(i, "INVALID_BLOCK");
      if (block.index !== i) return fail(i, "INDEX_MISMATCH: deletion, insertion, or reordering");
      if (block.prevHash !== previousHash) return fail(i, "PREVIOUS_HASH_MISMATCH");
      if (block.prevSignatureHash !== previousSignatureHash) {
        return fail(i, "PREVIOUS_SIGNATURE_MISMATCH");
      }
      if (!EVENTS.has(block.event)) return fail(i, "INVALID_EVENT");
      if (block.algorithm !== algorithm) return fail(i, "SIGNATURE_ALGORITHM_MISMATCH");

      let expectedPayloadHash: string;
      try {
        expectedPayloadHash = sha256(canonicalize(block.payload));
      } catch {
        return fail(i, "INVALID_PAYLOAD");
      }
      if (expectedPayloadHash !== block.payloadHash) return fail(i, "PAYLOAD_TAMPERED");

      const { hash, signature, ...unsigned } = block;
      if (blockHash(unsigned) !== hash) return fail(i, "BLOCK_HASH_MISMATCH");

      if (!checkSignature(hash, signature, { ...options, algorithm })) {
        return fail(i, "INVALID_SIGNATURE");
      }
      previousHash = hash;
      previousSignatureHash = signatureHash(signature);
    }
    return {
      valid: true,
      verifiedBlocks: blocks.length,
      totalBlocks: blocks.length,
      failedIndex: null,
      error: null,
    };
  }
}

/** Minimal framework-neutral wrapper for recording tool calls and outputs. */
export class AuditedAgent {
  readonly audit: AuditChain;

  constructor(audit: AuditChain) {
    this.audit = audit;
  }

  async runTool<T>(
    toolName: string,
    args: JSONValue,
    executor: (args: JSONValue) => Promise<T> | T,
  ): Promise<T> {
    this.audit.append("tool_call", { tool: toolName, arguments: args });
    try {
      const output = await executor(args);
      // The audit format is JSON-only. Reject non-JSON tool outputs.
      const safeOutput = JSON.parse(canonicalize(output)) as JSONValue;
      this.audit.append("tool_output", { tool: toolName, output: safeOutput, success: true });
      return output;
    } catch (error) {
      this.audit.append("tool_output", {
        tool: toolName,
        error: error instanceof Error ? error.message : String(error),
        success: false,
      });
      throw error;
    }
  }

  recordReasoning(summary: JSONValue): AuditBlock {
    return this.audit.append("llm_reasoning", summary);
  }

  recordDecision(decision: JSONValue): AuditBlock {
    return this.audit.append("final_decision", decision);
  }
}
