# zkleak

**How many bits does your zkVM guest's cycle count reveal about its private input?**

A zkVM proves your program ran correctly without revealing the inputs. But the
*number of cycles* it took is not covered by that guarantee — and if a loop bound
or a branch depends on a secret, the cycle count is a function of that secret.

zkleak measures exactly how many bits that is.

```
$ zkleak report sweep.csv

  H(S)   secret entropy      10.0000 bits
  I(S;O) leaked (Shannon)     4.0366 bits   <- average bits revealed
  min-entropy leakage         4.0875 bits   <- guessing advantage
  H(S|O) remaining            5.9634 bits

  single-guess success        1.6602%  (vs 0.0977% with no observation)
  largest identical class         64 secrets share one cycle count

  => the cycle count reveals 40.4% of the secret's entropy.
```

## Try it in 30 seconds

No zkVM required — example sweeps ship with the tool.

```bash
cargo build --release
./target/release/zkleak demo
```

`demo` walks through four cases: a negative control that must read zero, a guest
that leaks 4 bits, what padding it would cost, and the same guest under a
realistic (non-uniform) prior.

The bundled sweeps:

| file | shows |
|---|---|
| `negative-control.csv` | trip count fixed, data varies — must read **0.0000 bits** |
| `leaky-hash-lengths.csv` | padded buffer, unpadded loop — **4.04 bits** of a 10-bit secret |
| `oblivious-hash.csv` | the same guest with the loop padded too — back to **0.0000** |
| `skewed-prior.csv` | the same leak under a realistic prior — **1.53 bits**, not 4.04 |
| `issuer-collision.csv` | five issuers, three algorithms: leakage counts **classes, not secrets** |

The first four are real sweeps of a synthetic SP1 guest written for this purpose;
the fifth is constructed, with fictional issuers.

**Run the negative control first if you doubt the tool.** It holds the loop trip
count fixed while varying the data, so a correct implementation must print
exactly `0.0000 bits`. If it doesn't, nothing else here is trustworthy.

```bash
./target/release/zkleak selftest    # 17 checks against closed-form answers
```

Zero dependencies. Builds anywhere Rust does.

## Use it on your own guest

**Step 1 — sweep your guest under its *executor*.** Not the prover: executing is
seconds per sample, proving is minutes, and the cycle count is identical either
way.

```rust
// SP1
let (_out, report) = client.execute(ELF, stdin).run().unwrap();
println!("{},{}", secret, report.total_instruction_count());
```

RISC Zero: run the executor without proving and read the session's cycle count.
zkleak only reads integers, so any zkVM works.

A complete commented driver is in
[`examples/sp1-sweep-template.rs`](examples/sp1-sweep-template.rs) — copy it into
your project, change three marked lines, redirect stdout to a file.

> ### ⚠ The one mistake that invalidates everything
>
> **Hold the input size fixed across the sweep.** If the buffer you send grows
> with the secret, you are measuring deserialization cost mixed with control
> flow and cannot tell which one you found. Send a fixed-size padded buffer and
> pass the true length separately. The template does this.

**Step 2 — measure.**

```bash
zkleak report sweep.csv
```

**Step 3 — if it leaks, see what a fix costs.**

```bash
zkleak buckets sweep.csv
```

## The three commands

### `report` — how much does it leak?

| Line | Means |
|---|---|
| **Shannon leakage** | average bits revealed per proof |
| **min-entropy leakage** | guessing advantage — quote this one if the attacker gets a *single* observation, which is the usual zkVM case |
| **largest identical class** | how many secrets share a cycle count — your anonymity set |
| **single-guess success** | probability an optimal attacker names the secret first try |
| `0.0000 bits` | nothing leaks through this observable, over this sweep |

### `buckets` — what does mitigation cost?

Padding rounds every execution up to its bucket's maximum, making everything in
a bucket indistinguishable. With *k* buckets the min-entropy leakage is exactly
log₂(k), so only the *overhead* can be optimised — which zkleak does exactly, by
dynamic programming.

```
  k      min-entropy        Shannon mean overhead     overhead
  1           0.0000         0.0000         35895        1.85x
  2           1.0000         0.9917         16874        1.40x
  4           2.0000         1.9832          7364        1.17x
  8           3.0000         2.9656          2608        1.06x
```

`k=1` is full obliviousness. Note the shape: one bucket boundary buys most of
the overhead reduction for one bit. Overhead is in **cycles** — it does not
translate linearly into proving seconds, and zkleak makes no wall-clock claim.

### `scale` — what if the guest batches?

Costs of independent items convolve, so leakage for *n* items follows from a
single-item sweep:

```
  n         min-entropy  total Shannon   marginal (nth)
  1              4.0875         4.0366           4.0366
  8              7.0112         5.7551           0.0966
  64            10.0014         7.2559           0.0114
```

Total leakage grows about half a bit per doubling of the batch **as a whole**.

The last column is the *marginal* contribution of the n-th item,
`H(O_n) − H(O_n−1)`. It shrinks as roughly 1/n, which suggests — but is **not
equal to** — `I(L_i;O)`, the leakage about one specific item. Treat it as an
indicator, not that quantity.

Assumes items are i.i.d. and only the **sum** is observable — an observer who
sees per-item costs gains nothing from batching.

## Input format

```csv
secret,cycles
L1,1
L56,2
L120,3
```

Optional header. Third column is an optional prior weight (default 1). Real
input-length distributions are skewed rather than uniform, and it matters: the
same guest in `examples/` measures **4.04 bits** under a uniform prior but
**1.53 bits** under a realistic one. Uniform roughly doubles the apparent leak.

## What zkleak does not do

- **It finds nothing on its own.** You supply the sweep. It does not discover
  which program to check or which input is secret.
- **It cannot tell you whether anyone can *see* the cycle count.** A
  constant-size wrapped proof (e.g. Groth16) hides it entirely. zkleak reports
  what the *trace contains*; observability is a separate question about your
  deployment.
- **It only measures the observable you gave it.** Precompile counts, memory
  footprint and page counts are separate channels needing separate sweeps.
- **Secrets must be enumerable.** Lengths, indices, positions, categories — yes.
  Cryptographic keys — no; you cannot sweep 2²⁵⁶.
- **It gives no verdict.** It reports bits. Whether *N* bits matters is a
  property of your deployment, not of the arithmetic.

## Why the numbers are exact

Cycle counts from a zkVM executor are deterministic: same input, same count,
every time. (Verified on SP1: 128 executions with fixed control flow and varying
data produced *identical* counts, zero variance.)

So leakage here is **computed**, not estimated — no sampling error, no bias
correction, no confidence intervals. Classical side-channel work spends most of
its effort fighting measurement noise; this domain has none. If your sweep covers
the secret domain, the answer is arithmetic.

The flip side: this exactness holds for *cycle counts*, which are deterministic.
It does **not** hold for wall-clock proving time, which is noisy and
machine-dependent. zkleak deliberately measures only the former.

## Correctness

`zkleak selftest` checks 17 assertions against closed forms:

- SHA-256 block-count leakage — classes, Shannon, and min-entropy
- a constant observable (must be exactly 0)
- a bijective observable (must be exactly `H(S)`)
- the uniform-prior reduction of min-entropy leakage to log₂(k)
- a weighted, non-uniform prior
- hand-computed optimal-bucketing overheads

The SHA-256 case is a genuine external check. SHA-256 over an `L`-byte message
performs ⌈(L+9)/64⌉ compressions, so for `L` uniform on 1..1024 the secret space
partitions into 17 classes of sizes {55, 64×15, 9}, giving Shannon leakage
**4.036617** bits in closed form. Measured on a real SP1 guest: **4.0366**. The
derivation predicted the measurement, and the tool reproduces the derivation.

## The measures, precisely

- **Shannon leakage** `I(S;O) = H(S) − H(S|O)` — average bits learned.
- **Min-entropy leakage** `H∞(S) − H∞(S|O)` (Smith, 2009) — guessing advantage.
  Under a uniform prior this equals log₂(number of distinct cycle counts).
- **`H(S|O)`** — uncertainty remaining after the observation.
- **Single-guess success** — probability an optimal adversary is right first try,
  shown against the no-observation baseline.

## License

MIT — see [LICENSE-MIT](LICENSE-MIT).
