# Agent Code Writing Guidelines

**Purpose:** Prevent the generation of plausible-but-incorrect code. LLMs optimize for plausibility — code that compiles, passes tests, reads well, and is still fundamentally wrong. These guidelines exist because in distributed systems and cryptography, "plausible" can mean silently broken consensus, exploitable side channels, or O(n²) where O(log n) was required.

**Core principle:** Code is not correct because it compiles and tests pass. Code is correct when its critical invariants are identified, measured, and demonstrated.

---

## Part 1: Code Generation Rules

### 1.1 — Prefer Existing Tools Over New Code

Before writing anything, search for existing battle-tested solutions. The correct answer is often zero lines of code.

**Mandatory checklist before generating code:**

- Does the language ecosystem already have a standard tool for this? (e.g., `cargo-sweep`, `go tool pprof`, `openssl` CLI)
- Does the operating system already handle this? (e.g., `logrotate`, `systemd` timers, ext4 reserved blocks, `cron`)
- Is there a well-maintained library with an active security track record? (e.g., `ring` over hand-rolled crypto, `tonic` over raw gRPC, `quic-go` over custom transport)
- Can the problem be solved with configuration rather than code? (e.g., kernel tunables, filesystem mount options, systemd resource limits)

**Rule:** If the solution exists and is maintained, use it. Do not reimplement. If you must wrap it, the wrapper should be thin and its boundaries obvious. State explicitly why an existing tool was rejected before writing a replacement.

### 1.2 — Minimize Line Count Aggressively

Volume is not value. A 576,000-line reimplementation that misses a 4-line check is worse than the 4-line check. Every line is a liability.

- Before generating a module, state in a comment: "This module exists because [specific reason]. The closest existing solution is [X] and it was rejected because [specific gap]."
- If a function exceeds 50 lines, justify why it cannot be decomposed.
- If a dependency tree exceeds ~100 crates/modules for a focused project, audit whether the architecture has unnecessary abstraction layers.
- Never generate dashboard UIs, command palettes, or visualization layers unless the user explicitly requested them. Solve the actual problem first.

### 1.3 — Classify the Primary Invariant: Speed, Correctness, or Simplicity

Not all code has the same definition of "correct." The article's core lesson is *measure what matters* — but what matters depends entirely on what the code does. Applying speed optimization to code whose invariant is correctness is the same category of error as writing a query planner that does full table scans: you're measuring the wrong thing.

**Before writing any code, classify the primary invariant:**

| Category | Primary invariant | What "correct" means | What to measure |
|---|---|---|---|
| **Hot-path data processing** (query execution, page cache, serialization, network I/O loops) | **Speed** | The operation completes within a latency/throughput budget at scale | Latency percentiles, throughput, allocations per op, syscall count |
| **Cryptography & attestation** (signature verification, quote parsing, key derivation, constant-time operations) | **Correctness & simplicity** | The algorithm is faithful to the spec, has no side channels, and is simple enough to audit | Line count, branch count, adherence to spec, absence of timing variation, fuzz coverage |
| **Consensus & state machines** (Raft log replication, PBFT view changes, TEE key distribution protocol) | **Correctness** | State transitions match the protocol specification exactly, under all failure modes | Model checking coverage, partition behavior, determinism given the same input log |
| **Security boundaries** (input validation, trust boundary enforcement, policy evaluation) | **Correctness & completeness** | Every malformed or malicious input is rejected before reaching trusted code | Fuzz testing coverage, rejection rate on malformed inputs, absence of TOCTOU gaps |
| **Glue code & orchestration** (deployment scripts, CLI tools, config management) | **Simplicity** | It's obvious what it does, easy to debug, and easy to replace | Line count, dependency count, time-to-understand for a new reader |

**This classification drives everything downstream.** The right choice for a hot-path page cache (zero-copy, arena allocation, unsafe pointer management) is the *wrong* choice for attestation verification (where an extra copy is meaningless but an extra branch on secret data is a vulnerability). Specifically:

**When the invariant is speed:** Optimize. Benchmark. Eliminate allocations. Choose `fdatasync` over `fsync`. Use zero-copy. This is where the article's anti-patterns (`.to_vec()`, per-request schema reload, `sync_all`) are genuinely wrong.

**When the invariant is correctness (crypto, attestation, consensus):** Optimize for *auditability*. Fewer lines. Fewer branches. Faithful spec implementation over clever shortcuts. The measure is: can a reviewer read this function and verify it matches the spec in one pass? If not, it's too complex, regardless of how fast it is. Do not introduce early-exit optimizations. Do not skip validation steps for performance. Do not add caching of security decisions. Every "optimization" in this category is a potential bypass or side channel until proven otherwise.

**When the invariant is simplicity (glue code, tooling):** The measure is: could someone replace this with a shell one-liner? If yes, use the shell one-liner. This is the 82,000-line cleanup daemon mistake — applying implementation effort where the correct answer is `cron` + `find`.

**Rule:** Every module, file, or significant function must start with an `// INVARIANT CLASS:` comment declaring whether the primary invariant is speed, correctness, or simplicity. This classification determines which review criteria, which optimization strategies, and which anti-patterns apply. Misclassifying the invariant is the root cause of most agent-generated code failures.

### 1.4 — Identify and Document Specific Invariants

Once the invariant class is established, name the specific invariants the code must satisfy.

**Speed-class invariants (measure with benchmarks):**
- Primary key lookup must be O(log n).
- Sequential scan must stream without full materialization.
- WAL fsync strategy must be explicit and justified.
- Cache-hit path must be zero-copy.

**Correctness-class invariants (measure with audits, fuzzing, and spec compliance):**
- Constant-time comparison for all secret-dependent operations. No branching on secret data.
- Attestation quote signature must be verified before any field inside the quote is trusted.
- Key derivation parameters must match the specification exactly — no "equivalent" substitutions.
- Consensus state machine transitions must be deterministic given the same input log.
- Failure detection timeout must be bounded and configurable.

**Simplicity-class invariants (measure with line count and dependency count):**
- Can someone unfamiliar with the codebase understand this module in under 5 minutes?
- Does this have fewer dependencies than the problem strictly requires?
- Could this be replaced by a standard tool with no loss of functionality?

**Rule:** Before generating implementation code, emit a `// INVARIANT:` comment block listing every specific invariant the code must satisfy. These become the acceptance criteria. Tag each with its class so reviewers know which measurement to apply.

### 1.5 — Choose the Right Primitive, Not the Safe Default

"Safe defaults" compound into catastrophic slowdowns *in speed-class code*. Every system call, allocation strategy, and synchronization primitive must be chosen deliberately. Note: in correctness-class code (crypto, attestation), the "safe default" is often the *right* default — `sync_all` is fine if you're writing a key commitment log where data loss is a security failure.

**Specific patterns to avoid in speed-class code:**

| Anti-pattern | Why it's wrong | Correct alternative |
|---|---|---|
| `sync_all()` / `fsync` everywhere | Syncs metadata unnecessarily | `fdatasync` / `sync_data()` when metadata hasn't changed |
| `.to_vec()` on hot-path cache reads | Copies data that could be borrowed | Zero-copy via `Arc<[u8]>`, pinned buffers, or `Bytes` |
| `.clone()` of ASTs/IR in tight loops | Heap allocation per iteration | Reusable handles, arena allocation, or `Cow<'_, T>` |
| `Mutex<HashMap>` for concurrent reads | Write lock contention on read-heavy paths | `DashMap`, `RwLock`, or lock-free structures |
| Per-request schema reload | O(n) work on every operation | Cookie/version check, reload only on change |
| `format!()` / `.to_string()` in hot paths | Allocation + formatting when result may be unused | Lazy evaluation, guard checks before formatting |
| `serde_json::to_string` in logging | Serialization even when log level is disabled | Use `tracing` with lazy field evaluation |
| New allocations per operation | malloc/free pressure in tight loops | Object pools, arena allocators, or `SmallVec` |

**Rule:** For every system call or allocation in a hot path, add a comment: `// CHOSEN OVER [alternative] BECAUSE [reason]`. If you cannot name the alternative, you haven't thought about it enough.

### 1.6 — Write the Benchmark Before the Implementation

Not after. Not "when we optimize." Before.

- Define the benchmark workload based on realistic usage patterns, not synthetic best-cases.
- For databases: primary key lookup, range scan, concurrent writers, crash recovery.
- For crypto: operations/second for sign/verify/encrypt/decrypt at target key sizes, constant-time validation.
- For distributed systems: throughput at target cluster size, latency at p50/p99, behavior under network partition.
- For TEE workloads: attestation verification latency, encrypted channel setup time, memory overhead of confidential compute.

**Rule:** Every PR or code block that implements a performance-critical path must include or reference a benchmark. "We'll optimize later" is not acceptable for invariant-level operations. If the benchmark doesn't exist, the code isn't ready.

### 1.7 — Algorithm Selection Must Be Explicit

Never allow an algorithm choice to be implicit. The article's core bug was a query planner silently choosing a full table scan where a B-tree seek was required.

- When implementing search: state the expected complexity and why that data structure was chosen.
- When implementing consensus: name the protocol (Raft, PBFT, etc.) and cite the paper. Map every message type to the spec.
- When implementing key exchange: name the scheme, state the security level, and cite the standard.
- When implementing serialization on a hot path: justify the format choice (protobuf vs. flatbuffers vs. cap'n'proto vs. raw bytes) with the access pattern.

**Rule:** Every algorithm choice must appear as a comment: `// ALGORITHM: [name], O([complexity]) because [reason]. Alternative considered: [X], rejected because [reason].`

### 1.8 — Handle the Semantic Bugs, Not Just Syntax

LLMs rarely produce syntax errors. The bugs that matter are semantic: wrong algorithm, wrong syscall, wrong trust boundary, missing check. Structure code to make semantic bugs visible.

- Wrap critical invariants in `debug_assert!` (Rust) or build-tag-gated checks (Go) that verify the invariant holds at runtime during development.
- Use type-level encoding where possible: a `RowId` type that can only be constructed from a validated primary key lookup prevents accidental full-scan paths.
- For crypto: use distinct types for plaintext vs. ciphertext, signed vs. unsigned messages, attested vs. unattested data. Make it a compile error to confuse them.
- For distributed systems: encode node states as enums with explicit transition functions. Make illegal state transitions unrepresentable.

---

## Part 2: Prompting Guidelines

### 2.1 — Define Acceptance Criteria Before Generating Code

Never prompt with just intent ("implement a query planner", "build a disk cleanup tool"). Always include measurable acceptance criteria.

**Bad prompt:**
> Implement a B-tree backed key-value store in Rust.

**Also bad prompt:**
> Implement attestation quote verification in Rust. Optimize for speed — minimize allocations, use zero-copy parsing, and benchmark at 100k verifications/second.

This second prompt is bad because it misclassifies the invariant. Attestation verification is correctness-class code. Optimizing for speed introduces branch complexity and potential side channels. The correct metric is auditability and spec fidelity, not throughput.

**Good prompt (speed-class):**
> Implement a B-tree backed key-value store in Rust.
> **Invariant class: Speed.**
> Acceptance criteria:
> 1. Point lookup by key must use B-tree binary search descent, O(log n). Verify with a benchmark: 10,000 lookups on 1M keys must complete in under 50ms.
> 2. Range scans must iterate leaf pages without re-traversing from root.
> 3. Page reads from cache must be zero-copy (no `.to_vec()`).
> 4. Write path must use WAL with configurable fsync strategy (fdatasync by default, sync_all opt-in).
> 5. Include a benchmark binary that reports latency percentiles for get/put/scan operations.
> Before implementing, list the performance invariants and the algorithm chosen for each operation.

**Good prompt (correctness-class):**
> Implement SEV-SNP attestation report verification in Rust.
> **Invariant class: Correctness.**
> Acceptance criteria:
> 1. Must verify the VCEK signature over the report before reading any report field. No exceptions.
> 2. Must validate the certificate chain back to the AMD root of trust (ASK → VCEK).
> 3. Must check POLICY, MEASUREMENT, and HOST_DATA fields against expected values *after* signature verification.
> 4. No branching on report contents before signature is verified — treat the entire report as untrusted bytes until then.
> 5. Total implementation should be under 300 lines. If it's more, the abstraction is wrong.
> 6. Must be readable enough that a reviewer can verify spec compliance in a single pass.
> Do NOT optimize for speed. Do NOT add caching of verification results. Do NOT skip any validation step.

### 2.2 — Require the Agent to Research Before Implementing

Force the agent to study existing implementations before writing new code.

**Template:**
> Before writing any code:
> 1. Search for existing tools/libraries that solve this problem. List at least 3 candidates with their trade-offs.
> 2. If reimplementation is justified, study the reference implementation's key design decisions. For [X], the critical decisions are: [list them or ask the agent to identify them].
> 3. List the performance invariants that the reference implementation maintains.
> 4. Only then propose an implementation plan. Do not write code until the plan is reviewed.

### 2.3 — Demand Adversarial Self-Review

LLMs are sycophantic — they will praise their own output. Counter this explicitly.

**Append to any code generation prompt:**
> After generating the code:
> 1. Identify the 3 most likely semantic bugs (wrong algorithm, wrong syscall, missing edge case — not syntax errors).
> 2. For each hot-path function, state the time complexity and the allocation count per call.
> 3. List every system call in the write/commit path and justify each one.
> 4. Identify what existing tool or library could replace this code entirely. If one exists, explain why we're not using it.
> 5. Do NOT tell me the code "looks good" or the "architecture is sound." Tell me what's most likely wrong.

### 2.4 — Prompt for Minimal Solutions First

Complexity should be introduced only when simplicity is proven insufficient.

**Template:**
> Solve this problem with the minimum possible code. Start with the simplest approach that could work (even a shell one-liner or a config change). Only escalate to a library, then a service, then a system if the simpler approach fails a specific, stated requirement. At each level of escalation, state what requirement the simpler approach failed.

### 2.5 — Separate Research, Planning, and Implementation Phases

Never allow the agent to go from prompt to code in one shot. Require checkpoints.

**Phase 1 — Research:**
> What existing tools, libraries, or OS-level features solve [problem]? For each, state: maturity, maintenance status, dependency count, and whether it handles [specific edge case].

**Phase 2 — Design:**
> Given [chosen approach], list: (a) every performance invariant, (b) the algorithm for each critical operation with complexity, (c) every system call in the hot path, (d) the benchmark workload that will validate correctness.

**Phase 3 — Implementation:**
> Implement according to the approved design. For every deviation from the design, add a `// DEVIATION:` comment explaining why.

**Phase 4 — Validation:**
> Run the benchmarks defined in Phase 2. Report the results. Flag any metric that deviates more than 2x from the design target.

### 2.6 — Domain-Specific Prompt Addenda

Append these to any prompt in the relevant domain.

**For Rust code:**
> - No `.clone()` in any function called more than once per request without a `// CLONE JUSTIFIED:` comment.
> - No `.unwrap()` in library code. Use typed errors.
> - No `Box<dyn Trait>` on hot paths without measuring vtable dispatch overhead.
> - Prefer `&[u8]` / `Bytes` over `Vec<u8>` for read paths.
> - State the MSRV. Pin dependency versions for reproducibility.

**For Go code:**
> - No `interface{}` / `any` without a `// TYPE ERASURE JUSTIFIED:` comment.
> - No goroutine without a documented shutdown path.
> - Context propagation must be explicit — every function that can block takes `context.Context` as first argument.
> - No `sync.Mutex` protecting a map in a read-heavy path without considering `sync.RWMutex` or `sync.Map`.
> - Error wrapping must preserve the chain: `fmt.Errorf("operation: %w", err)`.

**For cryptography:**
> - Never implement a cryptographic primitive. Use `ring`, `boring`, `crypto/subtle`, or equivalent audited libraries.
> - All secret comparisons must use constant-time functions. No `==` on secrets.
> - Key material must be zeroized on drop (`zeroize` crate in Rust, explicit zeroing in Go).
> - State the threat model explicitly: what does the attacker control? What are they trying to learn?
> - For TEE code: attestation quote parsing must reject malformed input. Do not trust anything inside the quote until the signature is verified against the expected measurement.

**For distributed systems:**
> - Name the consistency model (linearizable, sequential, eventual, causal). Justify the choice.
> - Every RPC must have a timeout. Every timeout must be configurable.
> - State what happens during a network partition for every operation.
> - Idempotency: every write operation must state whether it's idempotent and how duplicate detection works.
> - Clock assumptions must be explicit: does this code require synchronized clocks? Within what bound?

---

## Part 3: Review Checklist

Use this checklist to review any agent-generated code before accepting it.

### Invariant Classification
- [ ] Every module/file declares its invariant class (speed, correctness, or simplicity)
- [ ] Speed-class optimizations are not applied to correctness-class code
- [ ] Correctness-class code is optimized for auditability, not throughput
- [ ] Simplicity-class code was evaluated for replacement by existing tools before implementation

### Correctness
- [ ] Every algorithm choice is named and its complexity stated
- [ ] Performance invariants are documented with `// INVARIANT:` comments
- [ ] A benchmark exists or is referenced for every hot-path operation
- [ ] The code does not reimplement something available in the standard library or a well-maintained dependency
- [ ] Error handling covers the failure modes, not just the happy path
- [ ] For crypto: no branching on secrets, no timing side channels, key material zeroized

### Performance (speed-class code only)
- [ ] No `.clone()`, `.to_vec()`, `format!()`, or allocation in hot paths without justification
- [ ] System calls (fsync, mmap, etc.) are chosen deliberately, not by default
- [ ] Cache-hit paths are zero-copy or near-zero-copy
- [ ] Benchmark results are within 2x of design targets

### Architecture
- [ ] Line count is proportional to problem complexity (not prompt complexity)
- [ ] No dashboard, UI, or visualization layer unless explicitly requested
- [ ] Dependency count is justified — each dependency solves a specific, stated problem
- [ ] Module boundaries correspond to failure domains, not to "clean architecture" abstractions

### Security (for TEE / crypto / distributed systems)
- [ ] Threat model is stated: who is the attacker, what do they control, what are they trying to achieve
- [ ] Trust boundaries are explicit in code (types, module boundaries, validation at ingress)
- [ ] Attestation paths validate before trusting
- [ ] No TOCTOU between check and use of security-critical values

---

## Part 4: Anti-Patterns to Reject Immediately

If you see any of these in agent-generated code, stop and rethink:

1. **"Sophisticated" solution to a simple problem.** If the problem is "delete old build artifacts," the answer is not 82,000 lines with a Bayesian scoring engine. Ask: what's the cron one-liner?

2. **All the right names, none of the right behavior.** A module called `query_planner` that plans every query as a full table scan. A module called `attestation_verifier` that doesn't check the measurement. The names are plausible. The behavior must be verified.

3. **Tests that verify the output format but not the invariant.** A test that checks "query returns rows" passes whether the query used a B-tree seek or a full scan. The test must check the *plan*, not just the *result*.

4. **LLM self-review that praises the code.** If the agent says "the architecture is clean and the error handling is thorough," it has told you nothing. Ask it to find the three most likely bugs instead.

5. **COCOMO-style metrics presented as evidence of value.** Lines of code, estimated development cost, number of modules — none of these measure correctness. Measure latency, throughput, and invariant compliance instead.

6. **"Safe defaults" without performance analysis.** `sync_all`, `Mutex`, `.clone()`, per-request allocation — each individually defensible, collectively catastrophic. Every "safe" choice on a hot path needs a performance justification.

7. **Reimplementation without studying the reference.** If you're implementing something that has a 26-year-old reference implementation, the first step is reading its commit history for the hard-won invariants, not generating code from API docs.

8. **Speed-optimizing correctness-class code.** If the code's job is to verify a cryptographic signature or enforce a trust boundary, "make it faster" is almost always the wrong goal. Every early exit is a potential bypass. Every cache is a potential TOCTOU. Every branch eliminated for speed is a validation step that might have mattered. The right question for correctness-class code is "can I make it simpler?" — fewer lines, fewer branches, more obvious spec correspondence. Speed is a rounding error when the alternative is a security vulnerability.
