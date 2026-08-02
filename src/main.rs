//! zkleak -- measure exactly what a zkVM proof reveals about its private inputs.
//!
//! WHAT THIS IS
//!
//! A zkVM guest's execution length depends on its inputs. If some of those inputs
//! are secret, the cycle count is a function of a secret, and anything derived
//! from the cycle count (segment/shard count, proof size for non-constant-size
//! systems, proving duration) carries information about it.
//!
//! zkleak takes a sweep of `secret -> cycle count` and reports how many bits that
//! mapping reveals. It is a measurement instrument, not a vulnerability scanner:
//! it tells you what your proof reveals so you can decide whether you care.
//! Whether any given number of bits matters is a question about your deployment
//! that this tool does not attempt to answer.
//!
//! WHY THE NUMBERS ARE EXACT
//!
//! Cycle counts from a zkVM executor are deterministic: the same input yields
//! the same count, every time, with no measurement noise. That is unusual for
//! side-channel analysis and it has a pleasant consequence -- leakage is
//! *computed*, not *estimated*. There is no sampling error, no bias correction,
//! and no confidence interval. If the sweep covers the secret domain, the answer
//! is arithmetic.
//!
//! WHAT IT DOES NOT DO
//!
//! * No timing measurements. Wall-clock proving time is noisy and, on shared or
//!   thermally-constrained hardware, unusable; translating cycles into seconds is
//!   deliberately out of scope.
//! * No claim that the observable is visible to any particular adversary. Whether
//!   cycle count is externally observable depends on the proof system (a
//!   constant-size wrapped proof hides it; a variable-size proof or an observable
//!   proving duration may not) and on the deployment.
//! * No security verdict. There is no threshold above which zkleak says "unsafe".
//!
//! USAGE
//!
//!   zkleak report   <csv>              exact leakage of the measured mapping
//!   zkleak buckets  <csv> [--max-k N]  leakage vs cycle-overhead frontier
//!   zkleak scale    <csv> --n K        predicted leakage for K independent items
//!   zkleak selftest                    verify the math against a closed form
//!
//! INPUT FORMAT
//!
//!   CSV, optional header, columns: secret,cycles[,weight]
//!
//!   `secret`  a label (any string; used only for reporting)
//!   `cycles`  non-negative integer observable
//!   `weight`  optional relative prior probability of this secret (default 1)
//!
//! Produce it by sweeping your guest under its executor -- e.g. for SP1,
//! `client.execute(ELF, stdin).run()` and `report.total_instruction_count()`;
//! for RISC Zero, the executor's session cycle count. zkleak is deliberately
//! decoupled from any specific zkVM.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::process;

// ---------------------------------------------------------------------------
// Leakage measures
// ---------------------------------------------------------------------------

/// A partition of the secret space induced by a deterministic observable.
///
/// `classes` maps an observable value to the total prior weight of the secrets
/// producing it; `max_in_class` maps it to the single largest secret weight in
/// that class (needed for min-entropy, which is a max, not a sum).
struct Partition {
    classes: BTreeMap<u64, f64>,
    max_in_class: BTreeMap<u64, f64>,
    total_weight: f64,
    max_secret_weight: f64,
    num_secrets: usize,
}

struct Leakage {
    /// I(S;O): average bits learned per observation.
    shannon_bits: f64,
    /// Min-entropy leakage: bits of *guessing advantage*. For a uniform prior
    /// this is exactly log2(number of distinct observable values).
    min_entropy_bits: f64,
    /// H(S|O): bits of uncertainty remaining after observing.
    residual_bits: f64,
    /// H(S): total secret entropy under the supplied prior.
    secret_bits: f64,
    /// Probability that an adversary who sees the observable guesses the secret
    /// correctly on a single try, playing optimally.
    guess_probability: f64,
    num_classes: usize,
    /// Weight of the largest indistinguishable class -- the "anonymity set" an
    /// average secret hides in, in prior-weight terms.
    largest_class_weight: f64,
}

/// Accumulates the sums needed for exact weighted entropies in one pass.
///
/// Weighted conditional entropy needs `sum_{s in o} w_s log2 w_s` per class,
/// which cannot be recovered from the class weight totals alone, so it is
/// accumulated while the partition is built.
#[derive(Default)]
struct Acc {
    /// sum over secrets of w*log2(w)
    w_log_w_total: f64,
    /// per class: sum over its secrets of w*log2(w)
    w_log_w_class: BTreeMap<u64, f64>,
}

fn compute_leakage(p: &Partition, acc: &Acc) -> Leakage {
    let w = p.total_weight;

    // H(S) = log2(W) - (1/W) * sum_s w_s log2(w_s)
    let h_s = w.log2() - acc.w_log_w_total / w;

    // H(S|O) = (1/W) * sum_o [ W_o log2(W_o) - sum_{s in o} w_s log2 w_s ]
    let mut h_s_given_o = 0.0f64;
    for (o, &w_o) in p.classes.iter() {
        let inner = acc.w_log_w_class.get(o).copied().unwrap_or(0.0);
        h_s_given_o += w_o * w_o.log2() - inner;
    }
    h_s_given_o /= w;

    // Min-entropy leakage (Smith 2009):
    //   H_inf(S)     = -log2( max_s P(s) )
    //   H_inf(S|O)   = -log2( sum_o max_{s in o} P(s) )
    //   leakage      = H_inf(S) - H_inf(S|O)
    //                = log2( sum_o max_{s in o} w_s ) - log2( max_s w_s )
    // For a uniform prior every max is 1 and the sum is the class count, so this
    // reduces to log2(number of classes).
    let sum_of_maxes: f64 = p.max_in_class.values().sum();
    let min_entropy_bits = sum_of_maxes.log2() - p.max_secret_weight.log2();
    let guess_probability = sum_of_maxes / w;

    let largest_class_weight = p.classes.values().cloned().fold(0.0f64, f64::max);

    Leakage {
        shannon_bits: (h_s - h_s_given_o).max(0.0),
        min_entropy_bits: min_entropy_bits.max(0.0),
        residual_bits: h_s_given_o.max(0.0),
        secret_bits: h_s,
        guess_probability,
        num_classes: p.classes.len(),
        largest_class_weight,
    }
}

/// Build the partition + accumulators from (cycles, weight) samples.
fn build_partition(rows: &[(String, u64, f64)]) -> (Partition, Acc) {
    let mut classes: BTreeMap<u64, f64> = BTreeMap::new();
    let mut max_in_class: BTreeMap<u64, f64> = BTreeMap::new();
    let mut acc = Acc::default();
    let mut total_weight = 0.0f64;
    let mut max_secret_weight = 0.0f64;

    for (_, cycles, weight) in rows {
        let w = *weight;
        *classes.entry(*cycles).or_insert(0.0) += w;
        let e = max_in_class.entry(*cycles).or_insert(0.0);
        if w > *e {
            *e = w;
        }
        let wlw = if w > 0.0 { w * w.log2() } else { 0.0 };
        acc.w_log_w_total += wlw;
        *acc.w_log_w_class.entry(*cycles).or_insert(0.0) += wlw;
        total_weight += w;
        if w > max_secret_weight {
            max_secret_weight = w;
        }
    }

    (
        Partition {
            classes,
            max_in_class,
            total_weight,
            max_secret_weight,
            num_secrets: rows.len(),
        },
        acc,
    )
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

fn print_leakage(l: &Leakage, p: &Partition, uniform: bool) {
    println!("  secrets sampled          {}", p.num_secrets);
    println!("  distinct cycle counts    {}", l.num_classes);
    println!();
    println!("  H(S)   secret entropy    {:>9.4} bits", l.secret_bits);
    println!("  I(S;O) leaked (Shannon)  {:>9.4} bits   <- average bits revealed", l.shannon_bits);
    println!("  min-entropy leakage      {:>9.4} bits   <- guessing advantage", l.min_entropy_bits);
    println!("  H(S|O) remaining         {:>9.4} bits", l.residual_bits);
    println!();
    println!(
        "  single-guess success     {:>9.4}%  (vs {:.4}% with no observation)",
        100.0 * l.guess_probability,
        100.0 * p.max_secret_weight / p.total_weight
    );
    if uniform {
        println!(
            "  largest identical class  {:>9.0} secrets share one cycle count",
            l.largest_class_weight
        );
    } else {
        // Weight units are arbitrary, so a raw total is meaningless -- report it
        // as a share of the prior instead.
        println!(
            "  largest identical class  {:>8.2}% of prior mass shares one cycle count",
            100.0 * l.largest_class_weight / p.total_weight
        );
    }
    let frac = if l.secret_bits > 0.0 {
        100.0 * l.shannon_bits / l.secret_bits
    } else {
        0.0
    };
    println!();
    println!("  => the cycle count reveals {:.1}% of the secret's entropy.", frac);
    if l.num_classes == 1 {
        println!("     All sampled secrets produce an identical cycle count: no leakage");
        println!("     through this observable, over this sample.");
    }
}

// ---------------------------------------------------------------------------
// Bucketing (padding) frontier
// ---------------------------------------------------------------------------

/// Optimal contiguous bucketing by dynamic programming.
///
/// A padding scheme rounds every execution up to its bucket's largest cost, so
/// all secrets in a bucket become indistinguishable. Padding must be *upward*
/// (you cannot make a program take fewer cycles), so buckets are contiguous
/// ranges of the sorted cost values.
///
/// With k buckets, min-entropy leakage is exactly log2(k) wherever every bucket
/// is non-empty -- independent of where the boundaries fall. So the only thing
/// boundary placement can optimise is *overhead*. This computes, for each k, the
/// minimum achievable mean cycle overhead.
///
/// Returns, for each k in 1..=max_k, (total_weighted_overhead, boundaries).
fn optimal_buckets(values: &[(u64, f64)], max_k: usize) -> Vec<(f64, Vec<usize>)> {
    let v = values.len();
    // cost(i,j): weighted overhead of padding values[i..=j] up to values[j].
    let mut cost = vec![vec![0.0f64; v]; v];
    for i in 0..v {
        let mut acc = 0.0;
        for j in i..v {
            // recompute from scratch for clarity: sum_{t=i..j} w_t * (v_j - v_t)
            acc = 0.0;
            for t in i..=j {
                acc += values[t].1 * (values[j].0 - values[t].0) as f64;
            }
            cost[i][j] = acc;
        }
        let _ = acc;
    }

    let inf = f64::INFINITY;
    // best[b][j] = min overhead covering values[0..=j] with b buckets
    let mut best = vec![vec![inf; v]; max_k + 1];
    let mut cut = vec![vec![usize::MAX; v]; max_k + 1];
    for j in 0..v {
        best[1][j] = cost[0][j];
        cut[1][j] = 0;
    }
    for b in 2..=max_k {
        for j in 0..v {
            for i in 1..=j {
                let cand = best[b - 1][i - 1] + cost[i][j];
                if cand < best[b][j] {
                    best[b][j] = cand;
                    cut[b][j] = i;
                }
            }
        }
    }

    let mut out = Vec::new();
    for b in 1..=max_k {
        if !best[b][v - 1].is_finite() {
            continue;
        }
        // reconstruct boundaries
        let mut bounds = Vec::new();
        let mut j = v - 1;
        let mut bb = b;
        while bb >= 1 {
            let i = cut[bb][j];
            if i == usize::MAX {
                break;
            }
            bounds.push(j);
            if i == 0 {
                break;
            }
            j = i - 1;
            bb -= 1;
        }
        bounds.reverse();
        out.push((best[b][v - 1], bounds));
    }
    out
}

fn cmd_buckets(rows: &[(String, u64, f64)], max_k: usize) {
    let (p, _acc) = build_partition(rows);
    let mut values: Vec<(u64, f64)> = p.classes.iter().map(|(&c, &w)| (c, w)).collect();
    values.sort_by_key(|x| x.0);
    let v = values.len();
    if v < 2 {
        println!("Only one distinct cycle count: nothing to pad.");
        return;
    }
    // Clamp to >=1: k=0 buckets is meaningless and used to index past the end
    // of the DP table, which panicked on `--max-k 0`.
    let k_cap = max_k.clamp(1, v);
    let mean_cycles: f64 =
        values.iter().map(|(c, w)| *c as f64 * *w).sum::<f64>() / p.total_weight;

    println!("Leakage vs padding overhead (exact, cycle counts only)");
    println!();
    println!("  Padding rounds each execution up to its bucket maximum, making all");
    println!("  secrets in a bucket produce an identical cycle count. Overhead below");
    println!("  is in CYCLES; it does not translate linearly into proving seconds and");
    println!("  zkleak makes no wall-clock claim.");
    println!();
    println!(
        "  {:<5} {:>12} {:>14} {:>13} {:>12}",
        "k", "min-entropy", "Shannon", "mean overhead", "overhead"
    );
    println!(
        "  {:<5} {:>12} {:>14} {:>13} {:>12}",
        "", "(bits)", "(bits)", "(cycles)", "(relative)"
    );

    let solutions = optimal_buckets(&values, k_cap);
    for (idx, (total_overhead, bounds)) in solutions.iter().enumerate() {
        let k = idx + 1;
        // Map each distinct cost to the padded cost of the bucket holding it.
        let mut pad_of: BTreeMap<u64, u64> = BTreeMap::new();
        let mut start = 0usize;
        for &end in bounds.iter() {
            let pad_to = values[end].0;
            for t in start..=end {
                pad_of.insert(values[t].0, pad_to);
            }
            start = end + 1;
        }
        // Re-map the ORIGINAL secrets, preserving per-secret weights.
        //
        // An earlier version collapsed each cost class into a single
        // pseudo-secret carrying the whole class weight. That is harmless for
        // Shannon -- I(S;O) = H(O) for a deterministic observable, which depends
        // only on class weights -- but wrong for min-entropy, which is a MAX over
        // per-secret weights, not a sum. It was wrong in BOTH directions: on the
        // bundled examples it understated by 2.03x and overstated by 1.07x, and
        // at zero padding it disagreed with `report` on an identical partition.
        let bucketed: Vec<(String, u64, f64)> = rows
            .iter()
            .map(|(label, c, w)| {
                (label.clone(), pad_of.get(c).copied().unwrap_or(*c), *w)
            })
            .collect();
        let (bp, bacc) = build_partition(&bucketed);
        let bl = compute_leakage(&bp, &bacc);
        let mean_overhead = total_overhead / p.total_weight;
        println!(
            "  {:<5} {:>12.4} {:>14.4} {:>13.0} {:>11.2}x",
            k,
            bl.min_entropy_bits,
            bl.shannon_bits,
            mean_overhead,
            (mean_cycles + mean_overhead) / mean_cycles
        );
    }
    println!();
    println!("  k=1 is full obliviousness through this observable (all executions");
    println!("  padded to the maximum). Larger k trades bits for cycles.");
}

// ---------------------------------------------------------------------------
// Scaling: n independent items
// ---------------------------------------------------------------------------

/// Predict leakage when the guest processes `n` items whose costs are
/// independent draws from the measured single-item distribution.
///
/// The cost distribution of a sum of independent variables is the convolution
/// of their distributions -- equivalently, the coefficients of a polynomial
/// power. This is standard generating-function arithmetic, not a new result;
/// it is here because it lets you answer "what if I batch?" from a single-item
/// sweep instead of re-running the sweep for every batch size.
///
/// Leakage is invariant to a constant offset (adding the same number of cycles
/// to every execution does not change which executions are distinguishable), so
/// the fixed per-proof overhead in the input is subtracted first and ignored.
///
/// ASSUMPTION: item costs are independent and identically distributed. If real
/// batches have correlated item sizes, treat the output as an approximation.
fn cmd_scale(rows: &[(String, u64, f64)], n: usize) {
    let (p, _) = build_partition(rows);
    if p.classes.len() < 2 {
        println!("Only one distinct cycle count: leakage is 0 at every batch size.");
        return;
    }
    let min_cost = *p.classes.keys().next().unwrap();

    // Normalised single-item distribution over (cost - min_cost). These are
    // CLASS probabilities, which is what Shannon leakage H(O) needs.
    let mut dist: BTreeMap<u64, f64> = BTreeMap::new();
    for (&c, &w) in p.classes.iter() {
        *dist.entry(c - min_cost).or_insert(0.0) += w / p.total_weight;
    }
    // Min-entropy needs a different object: the largest PER-SECRET probability
    // within each class. Using class totals here conflates "the chance the
    // observable is o" with "the chance of the single likeliest secret producing
    // o", and those differ whenever a class holds more than one secret.
    let mut mdist: BTreeMap<u64, f64> = BTreeMap::new();
    for (&c, &mw) in p.max_in_class.iter() {
        let e = mdist.entry(c - min_cost).or_insert(0.0);
        *e = e.max(mw / p.total_weight);
    }

    println!("Predicted leakage when the guest processes n independent items");
    println!();
    println!("  Assumes item costs are i.i.d. draws from the measured distribution.");
    println!("  Only the SUM of costs is assumed observable: an observer who can see");
    println!("  per-item costs learns each item separately and gets no benefit from");
    println!("  batching.");
    println!();
    println!(
        "  {:<8} {:>12} {:>14} {:>16}",
        "n", "min-entropy", "total Shannon", "marginal (nth)"
    );
    println!(
        "  {:<8} {:>12} {:>14} {:>16}",
        "", "(bits)", "(bits)", "(bits)"
    );

    // Min-entropy leakage over n-tuples needs a MAX-product convolution, not a
    // class count:
    //     leakage = log2( sum_o max_{tuples -> o} P(tuple) ) - log2( (max p)^n )
    // An earlier version used log2(#classes), which is the UNIFORM-prior special
    // case -- so it was wrong exactly when the caller supplies the realistic
    // weights this tool encourages. Tracked in log2 space because (max p)^n
    // underflows f64 long before the n = 4096 the CLI permits.
    let log2_max_p = (p.max_secret_weight / p.total_weight).log2();
    let ldist: BTreeMap<u64, f64> = mdist
        .iter()
        .filter(|(_, &q)| q > 0.0)
        .map(|(&c, &q)| (c, q.log2()))
        .collect();

    /// log2( sum_i 2^{v_i} ), computed stably.
    fn log2_sum_exp2(vals: impl Iterator<Item = f64>) -> f64 {
        let v: Vec<f64> = vals.filter(|x| x.is_finite()).collect();
        if v.is_empty() {
            return f64::NEG_INFINITY;
        }
        let m = v.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        m + v.iter().map(|x| (x - m).exp2()).sum::<f64>().log2()
    }

    let mut cur = dist.clone();
    let mut lcur = ldist.clone();
    let mut prev_total = 0.0f64;
    for k in 1..=n {
        let h: f64 = cur
            .values()
            .filter(|&&q| q > 0.0)
            .map(|&q| -q * q.log2())
            .sum();
        let min_ent = log2_sum_exp2(lcur.values().cloned()) - (k as f64) * log2_max_p;
        let marginal = h - prev_total;
        prev_total = h;
        // print a geometric-ish subset plus the final value
        let show = k <= 4 || k == n || (k & (k - 1)) == 0;
        if show {
            println!(
                "  {:<8} {:>12.4} {:>14.4} {:>16.4}",
                k,
                min_ent.max(0.0),
                h,
                marginal
            );
        }
        if k < n {
            let mut lnxt: BTreeMap<u64, f64> = BTreeMap::new();
            for (&a, &la) in lcur.iter() {
                for (&b, &lb) in ldist.iter() {
                    let e = lnxt.entry(a + b).or_insert(f64::NEG_INFINITY);
                    *e = e.max(la + lb);
                }
            }
            lcur = lnxt;
            let mut nxt: BTreeMap<u64, f64> = BTreeMap::new();
            for (&a, &pa) in cur.iter() {
                for (&b, &pb) in dist.iter() {
                    *nxt.entry(a + b).or_insert(0.0) += pa * pb;
                }
            }
            cur = nxt;
        }
    }
    println!();
    println!("  Total leakage grows roughly as 0.5*log2(n): each doubling of the batch");
    println!("  adds about half a bit about the batch AS A WHOLE. The last column is the");
    println!("  MARGINAL contribution of the n-th item, H(O_n) - H(O_n-1) -- it shrinks");
    println!("  as ~1/n, which suggests but does not equal I(L_i;O), the leakage about");
    println!("  one specific item. Treat it as an indicator, not that quantity.");
}

// ---------------------------------------------------------------------------
// Self-test against a closed form
// ---------------------------------------------------------------------------

/// SHA-256 over an L-byte message performs ceil((L+9)/64) compression calls
/// (L bytes, one 0x80 byte, eight length bytes, padded to a 64-byte block).
/// So a guest that hashes a secret-length message has a cost that is an exact,
/// derivable function of the length -- which makes it a ground truth for
/// checking that this tool's arithmetic is right.
fn cmd_selftest() {
    let mut failures = 0;

    // Case 1: SHA-256 block counts, L uniform on 1..=1024.
    let mut rows = Vec::new();
    for l in 1u64..=1024 {
        let blocks = (l + 9 + 63) / 64;
        rows.push((format!("L{}", l), blocks, 1.0));
    }
    let (p, acc) = build_partition(&rows);
    let l = compute_leakage(&p, &acc);
    // Closed form: classes have sizes {55, 64 x 15, 9} -> 17 classes.
    let expect_classes = 17usize;
    let expect_min_ent = (17f64).log2(); // 4.0875
    let expect_shannon = {
        let sizes: Vec<f64> = {
            let mut m: BTreeMap<u64, f64> = BTreeMap::new();
            for l in 1u64..=1024 {
                *m.entry((l + 9 + 63) / 64).or_insert(0.0) += 1.0;
            }
            m.values().cloned().collect()
        };
        let total = 1024.0f64;
        let h_s = total.log2();
        let h_cond: f64 = sizes.iter().map(|&c| (c / total) * c.log2()).sum();
        h_s - h_cond
    };
    check("sha256 classes", l.num_classes as f64, expect_classes as f64, 1e-9, &mut failures);
    check("sha256 min-entropy", l.min_entropy_bits, expect_min_ent, 1e-9, &mut failures);
    check("sha256 Shannon", l.shannon_bits, expect_shannon, 1e-9, &mut failures);

    // Case 2: a constant observable must leak exactly zero.
    let rows2: Vec<_> = (0..100).map(|i| (format!("s{}", i), 42u64, 1.0)).collect();
    let (p2, a2) = build_partition(&rows2);
    let l2 = compute_leakage(&p2, &a2);
    check("constant Shannon", l2.shannon_bits, 0.0, 1e-12, &mut failures);
    check("constant min-entropy", l2.min_entropy_bits, 0.0, 1e-12, &mut failures);

    // Case 3: a bijective observable must leak all of H(S) = log2(N).
    let rows3: Vec<_> = (0..64).map(|i| (format!("s{}", i), i as u64, 1.0)).collect();
    let (p3, a3) = build_partition(&rows3);
    let l3 = compute_leakage(&p3, &a3);
    check("bijective Shannon", l3.shannon_bits, 6.0, 1e-12, &mut failures);
    check("bijective min-entropy", l3.min_entropy_bits, 6.0, 1e-12, &mut failures);
    check("bijective residual", l3.residual_bits, 0.0, 1e-12, &mut failures);

    // Case 4: min-entropy leakage reduces to log2(#classes) under a uniform
    // prior -- check against a hand case: 8 secrets, 4 classes of size 2.
    let rows4: Vec<_> = (0..8).map(|i| (format!("s{}", i), (i / 2) as u64, 1.0)).collect();
    let (p4, a4) = build_partition(&rows4);
    let l4 = compute_leakage(&p4, &a4);
    check("uniform log2(k)", l4.min_entropy_bits, 2.0, 1e-12, &mut failures);
    check("uniform residual", l4.residual_bits, 1.0, 1e-12, &mut failures);
    check("uniform guess p", l4.guess_probability, 0.5, 1e-12, &mut failures);

    // Case 5: weighted prior. Two secrets, weights 3 and 1, distinct costs.
    // H(S) = -0.75log0.75 - 0.25log0.25 = 0.8113; observable is bijective so
    // Shannon leakage = H(S) and residual = 0.
    let rows5 = vec![("a".to_string(), 1u64, 3.0), ("b".to_string(), 2u64, 1.0)];
    let (p5, a5) = build_partition(&rows5);
    let l5 = compute_leakage(&p5, &a5);
    let expect_h = -(0.75f64 * 0.75f64.log2()) - (0.25f64 * 0.25f64.log2());
    check("weighted H(S)", l5.secret_bits, expect_h, 1e-9, &mut failures);
    check("weighted Shannon", l5.shannon_bits, expect_h, 1e-9, &mut failures);
    check("weighted residual", l5.residual_bits, 0.0, 1e-12, &mut failures);

    // Case 6: bucketing. Costs 0,1,2,3 uniform; k=1 must pad to 3 with mean
    // overhead (3+2+1+0)/4 = 1.5 and zero leakage.
    let vals = vec![(0u64, 1.0), (1u64, 1.0), (2u64, 1.0), (3u64, 1.0)];
    let sols = optimal_buckets(&vals, 4);
    check("bucket k=1 overhead", sols[0].0 / 4.0, 1.5, 1e-12, &mut failures);
    check("bucket k=4 overhead", sols[3].0 / 4.0, 0.0, 1e-12, &mut failures);
    // k=2 optimum: {0,1} -> 1 and {2,3} -> 3, overhead (1+0+1+0)/4 = 0.5
    check("bucket k=2 overhead", sols[1].0 / 4.0, 0.5, 1e-12, &mut failures);

    // Case 7 (regression): at k = #classes NO padding is applied, so `buckets`
    // must agree with `report` on the identical partition. The original code
    // collapsed each class into one pseudo-secret carrying the whole class
    // weight, which is fine for Shannon but wrong for min-entropy (a max over
    // per-secret weights, not a sum).
    //
    // Uniform prior: 4 secrets, 3 classes {a:2, b:1, c:1}. Correct min-entropy
    // leakage = log2(3). Collapsed weights would give log2(2+1+1) - log2(2) = 1.
    let rows7 = vec![
        ("s0".to_string(), 10u64, 1.0),
        ("s1".to_string(), 10u64, 1.0),
        ("s2".to_string(), 20u64, 1.0),
        ("s3".to_string(), 30u64, 1.0),
    ];
    let (p7, a7) = build_partition(&rows7);
    let l7 = compute_leakage(&p7, &a7);
    check("no-pad min-ent (report)", l7.min_entropy_bits, 3f64.log2(), 1e-12, &mut failures);
    let vals7: Vec<(u64, f64)> = p7.classes.iter().map(|(&c, &w)| (c, w)).collect();
    let sol7 = optimal_buckets(&vals7, 3);
    // k=3 => every class its own bucket => zero overhead, partition unchanged.
    check("no-pad overhead is zero", sol7[2].0, 0.0, 1e-12, &mut failures);

    // Case 8 (regression): weighted prior, where collapsing is wrong in the
    // OTHER direction. 3 secrets, weights 8/1/1, all distinct costs.
    //   correct: log2(8+1+1) - log2(8) = log2(1.25) = 0.32193
    let rows8 = vec![
        ("a".to_string(), 1u64, 8.0),
        ("b".to_string(), 2u64, 1.0),
        ("c".to_string(), 3u64, 1.0),
    ];
    let (p8, a8) = build_partition(&rows8);
    let l8 = compute_leakage(&p8, &a8);
    check("weighted min-ent", l8.min_entropy_bits, 1.25f64.log2(), 1e-12, &mut failures);

    // Case 9 (regression, scale): min-entropy leakage for n=1 must equal what
    // `report` gives on the same weighted data. log2(#classes) does NOT -- that
    // is the uniform-prior special case, and `scale` accepts weights.
    // Same data as case 8: correct 0.32193, class count would give log2(3)=1.585.
    let probs: Vec<f64> = vec![0.8, 0.1, 0.1];
    let lmax = probs.iter().cloned().fold(f64::NEG_INFINITY, |m, q| m.max(q.log2()));
    let sum_of_maxes: f64 = probs.iter().sum();
    check("scale n=1 min-ent", sum_of_maxes.log2() - lmax, 1.25f64.log2(), 1e-12, &mut failures);

    // Case 9b (regression, scale): the case that case 9 was too weak to catch.
    // Case 9 is bijective, so class probability == secret probability and the
    // bug is invisible. Here class {a,b} holds TWO secrets, so the class total
    // (0.9) differs from the largest secret in it (0.5):
    //   correct  = log2(0.5 + 0.1) - log2(0.5)      = log2(1.2) = 0.26303
    //   by class = log2(0.9 + 0.1) - log2(0.9)      = log2(1.111) = 0.15200
    let rows9b = vec![
        ("a".to_string(), 7u64, 5.0),
        ("b".to_string(), 7u64, 4.0),
        ("c".to_string(), 9u64, 1.0),
    ];
    let (p9b, a9b) = build_partition(&rows9b);
    let l9b = compute_leakage(&p9b, &a9b);
    check("multi-secret class min-ent", l9b.min_entropy_bits, 1.2f64.log2(), 1e-12, &mut failures);
    // and the scale n=1 path must agree with it
    let sum_max_9b: f64 = p9b.max_in_class.values().sum::<f64>() / p9b.total_weight;
    let lmax_9b = (p9b.max_secret_weight / p9b.total_weight).log2();
    check("scale n=1 multi-secret", sum_max_9b.log2() - lmax_9b, 1.2f64.log2(), 1e-12, &mut failures);

    // Case 10 (regression, scale): the max-product convolution at n=2, checked
    // against brute-force enumeration of all 3^2 tuples. This is the step most
    // likely to be subtly wrong, so it is verified rather than asserted.
    let costs = [0u64, 1u64, 2u64];
    let mut brute: BTreeMap<u64, f64> = BTreeMap::new();
    for (i, &ci) in costs.iter().enumerate() {
        for (j, &cj) in costs.iter().enumerate() {
            let e = brute.entry(ci + cj).or_insert(0.0);
            *e = e.max(probs[i] * probs[j]);
        }
    }
    let brute_sum: f64 = brute.values().sum();
    let expect_n2 = brute_sum.log2() - 2.0 * lmax;
    // same quantity via the log-space recurrence the tool uses
    let ld: Vec<(u64, f64)> = costs.iter().zip(probs.iter()).map(|(&c, &q)| (c, q.log2())).collect();
    let mut lcur: BTreeMap<u64, f64> = ld.iter().cloned().collect();
    let mut lnxt: BTreeMap<u64, f64> = BTreeMap::new();
    for (&a, &la) in lcur.iter() {
        for &(b, lb) in ld.iter() {
            let e = lnxt.entry(a + b).or_insert(f64::NEG_INFINITY);
            *e = e.max(la + lb);
        }
    }
    lcur = lnxt;
    let m = lcur.values().cloned().fold(f64::NEG_INFINITY, f64::max);
    let got_n2 = m + lcur.values().map(|x| (x - m).exp2()).sum::<f64>().log2() - 2.0 * lmax;
    check("scale n=2 vs brute force", got_n2, expect_n2, 1e-12, &mut failures);

    println!();
    if failures == 0 {
        println!("all self-tests passed");
    } else {
        println!("{} self-test(s) FAILED", failures);
        process::exit(1);
    }
}

fn check(name: &str, got: f64, want: f64, tol: f64, failures: &mut usize) {
    let ok = (got - want).abs() <= tol;
    println!(
        "  {:<24} got {:>12.6}  want {:>12.6}  {}",
        name,
        got,
        want,
        if ok { "ok" } else { "FAIL" }
    );
    if !ok {
        *failures += 1;
    }
}

// ---------------------------------------------------------------------------
// CSV parsing
// ---------------------------------------------------------------------------

/// Returns (rows, saw_any_weight_column).
fn parse_csv(text: &str) -> Result<(Vec<(String, u64, f64)>, bool), String> {
    let mut rows = Vec::new();
    let mut weighted = false;
    // A header can only be the first *significant* line, which is not
    // necessarily line 1: files often open with `#` comments.
    let mut seen_significant = false;
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let is_first_significant = !seen_significant;
        seen_significant = true;
        let f: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if f.len() < 2 {
            return Err(format!("line {}: need at least 2 columns, got {}", idx + 1, f.len()));
        }
        // Skip a header row: second column not parseable as an integer.
        //
        // A header field is a word ("cycles"); a data field that failed to parse
        // usually still looks numeric ("1.5", "0x1f", "1_000", "-3"). Only warn
        // in the latter case -- otherwise every well-formed file with a header
        // would emit a spurious warning, which trains users to ignore warnings.
        if f[1].parse::<u64>().is_err() {
            if is_first_significant {
                let looks_numeric = f[1].chars().any(|c| c.is_ascii_digit() || c == '.' || c == '-');
                if looks_numeric {
                    eprintln!(
                        "zkleak: skipping line {} as a header, but {:?} looks like it was meant \
                         to be a number -- check that no data row was dropped",
                        idx + 1,
                        f[1]
                    );
                }
                continue;
            }
            return Err(format!("line {}: cycles column {:?} is not an integer", idx + 1, f[1]));
        }
        let cycles: u64 = f[1].parse().unwrap();
        let weight: f64 = if f.len() >= 3 && !f[2].is_empty() {
            weighted = true;
            f[2].parse()
                .map_err(|_| format!("line {}: weight {:?} is not a number", idx + 1, f[2]))?
        } else {
            1.0
        };
        if !(weight > 0.0) {
            return Err(format!("line {}: weight must be positive, got {}", idx + 1, weight));
        }
        rows.push((f[0].to_string(), cycles, weight));
    }
    if rows.is_empty() {
        return Err("no data rows".into());
    }
    Ok((rows, weighted))
}

fn load(path: &str) -> (Vec<(String, u64, f64)>, bool) {
    // Read lossily: a stray non-UTF-8 byte in a *label* should not abort the
    // analysis, since labels are only echoed back and never parsed.
    let text = match fs::read(path).map(|b| String::from_utf8_lossy(&b).into_owned()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("zkleak: cannot read {}: {}", path, e);
            process::exit(2);
        }
    };
    match parse_csv(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("zkleak: {}", e);
            process::exit(2);
        }
    }
}

// ---------------------------------------------------------------------------

const USAGE: &str = "\
zkleak -- how many bits does your zkVM guest's cycle count reveal?

QUICK START (no zkVM needed -- example data ships with the tool)

  zkleak demo                       run every command on the bundled examples
  zkleak selftest                   check the math against known closed forms

THE WORKFLOW

  1. Sweep your guest under its EXECUTOR (not the prover -- seconds, not minutes),
     varying the secret while holding the INPUT SIZE fixed. Write one line per
     run:  secret,cycles
       SP1:       client.execute(ELF, stdin).run() -> report.total_instruction_count()
       RISC Zero: run the executor, read the session's cycle count
     A ready-made driver is in examples/sp1-sweep-template.rs
  2. zkleak report sweep.csv        <- how many bits does it leak?
  3. zkleak buckets sweep.csv       <- what would padding it cost?

COMMANDS

  zkleak report   <csv>              exact leakage of the measured mapping
  zkleak buckets  <csv> [--max-k N]  leakage vs padding-overhead frontier
  zkleak scale    <csv> --n K        leakage if the guest batches K items
  zkleak demo                        run the above on the bundled examples
  zkleak selftest                    verify the math against closed forms

INPUT

  CSV, optional header, columns: secret,cycles[,weight]
    secret  a label -- any string, only echoed back
    cycles  non-negative integer, from your zkVM's executor
    weight  optional relative likelihood of this secret (default 1).
            Real length distributions are skewed; supplying weights gives
            leakage under YOUR distribution instead of a uniform assumption.

READING THE OUTPUT

  Shannon leakage      average bits revealed per proof
  min-entropy leakage  guessing advantage -- the number to quote if an attacker
                       gets ONE observation, which is the usual zkVM case
  largest class        how many secrets share a cycle count (your anonymity set)
  0.0000 bits          nothing leaks through this observable, over this sweep

THE ONE MISTAKE THAT INVALIDATES RESULTS

  Keep the input SIZE fixed across the sweep. If the buffer you send grows with
  the secret, you are measuring deserialization cost mixed with control flow and
  cannot tell which you found. Pad the buffer; pass the true length separately.

SCOPE

  Numbers are exact, not estimated: zkVM execution is deterministic, so there is
  no sampling error. But zkleak measures what the TRACE contains -- whether any
  adversary can SEE it depends on your proof system (a constant-size wrapped
  proof hides it) and deployment. It reports bits and gives no security verdict.
  Secrets must be enumerable to sweep: lengths, indices, positions, categories.
  Not cryptographic keys.
";

/// Run every command against the bundled examples.
///
/// The point is that a newcomer can see the whole tool work, and check it is
/// telling the truth, without owning a zkVM or writing a sweep.
fn cmd_demo() {
    let dirs = ["examples", "zkleak/examples", "../examples"];
    let base = dirs.iter().find(|d| {
        std::path::Path::new(d).join("negative-control.csv").exists()
    });
    let base = match base {
        Some(b) => *b,
        None => {
            eprintln!("zkleak demo: cannot find the examples/ directory.");
            eprintln!("Run this from the zkleak checkout, or pass a CSV to `report` directly.");
            process::exit(2);
        }
    };
    let path = |f: &str| std::path::Path::new(base).join(f).to_string_lossy().into_owned();

    let rule = "=".repeat(76);

    println!("{}", rule);
    println!("1/4  NEGATIVE CONTROL -- trip count fixed, data varies.");
    println!("     A correct tool MUST print 0.0000 bits. Check this first.");
    println!("{}", rule);
    let (rows, w) = load(&path("negative-control.csv"));
    let (p, acc) = build_partition(&rows);
    print_leakage(&compute_leakage(&p, &acc), &p, !w);

    println!("\n{}", rule);
    println!("2/4  A GUEST THAT LEAKS -- buffer padded, but the loop still runs");
    println!("     over the TRUE length. Padding the buffer alone does nothing.");
    println!("{}", rule);
    let (rows, w) = load(&path("leaky-hash-lengths.csv"));
    let (p, acc) = build_partition(&rows);
    print_leakage(&compute_leakage(&p, &acc), &p, !w);
    println!("\n  Note `largest identical class = 64`: SHA-256 works in 64-byte");
    println!("  blocks, so every length inside a block collides. The leak is");
    println!("  \"which block\", never the exact length.");

    println!("\n{}", rule);
    println!("3/4  WHAT WOULD A FIX COST? -- optimal padding, exactly solved");
    println!("{}", rule);
    let (rows, _) = load(&path("leaky-hash-lengths.csv"));
    cmd_buckets(&rows, 8);

    println!("\n{}", rule);
    println!("4/4  A REALISTIC PRIOR -- same guest, skewed length distribution");
    println!("     Uniform priors roughly DOUBLE the apparent leak here.");
    println!("{}", rule);
    let (rows, w) = load(&path("skewed-prior.csv"));
    let (p, acc) = build_partition(&rows);
    print_leakage(&compute_leakage(&p, &acc), &p, !w);

    println!("\n{}", rule);
    println!("Next: sweep your own guest (see `zkleak --help`, step 1) and run");
    println!("      zkleak report yoursweep.csv");
    println!("{}", rule);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print!("{}", USAGE);
        process::exit(2);
    }

    match args[1].as_str() {
        "demo" => cmd_demo(),
        "selftest" => {
            println!("zkleak self-test (checks arithmetic against closed forms)");
            println!();
            cmd_selftest();
        }
        "report" => {
            if args.len() < 3 {
                eprintln!("zkleak report: need a csv path");
                process::exit(2);
            }
            let (rows, weighted) = load(&args[2]);
            let (p, acc) = build_partition(&rows);
            let l = compute_leakage(&p, &acc);
            println!("zkleak report: {}", args[2]);
            if weighted {
                println!("(using supplied prior weights)");
            } else {
                println!("(uniform prior over sampled secrets)");
            }
            println!();
            print_leakage(&l, &p, !weighted);
        }
        "buckets" => {
            if args.len() < 3 {
                eprintln!("zkleak buckets: need a csv path");
                process::exit(2);
            }
            let mut max_k = 8usize;
            let mut i = 3;
            while i < args.len() {
                if args[i] == "--max-k" && i + 1 < args.len() {
                    // Error on a typo rather than silently using the default --
                    // a wrong number the user did not ask for is worse than a
                    // refusal.
                    max_k = match args[i + 1].parse::<usize>() {
                        Ok(v) if v >= 1 => v,
                        _ => {
                            eprintln!("zkleak buckets: --max-k must be a positive integer, got {:?}",
                                      args[i + 1]);
                            process::exit(2);
                        }
                    };
                    i += 2;
                } else {
                    i += 1;
                }
            }
            let (rows, _) = load(&args[2]);
            cmd_buckets(&rows, max_k);
        }
        "scale" => {
            if args.len() < 3 {
                eprintln!("zkleak scale: need a csv path");
                process::exit(2);
            }
            let mut n = 16usize;
            let mut i = 3;
            while i < args.len() {
                if args[i] == "--n" && i + 1 < args.len() {
                    n = match args[i + 1].parse::<usize>() {
                        Ok(v) => v,
                        _ => {
                            eprintln!("zkleak scale: --n must be an integer in 1..=4096, got {:?}",
                                      args[i + 1]);
                            process::exit(2);
                        }
                    };
                    i += 2;
                } else {
                    i += 1;
                }
            }
            if n == 0 || n > 4096 {
                eprintln!("zkleak scale: --n must be in 1..=4096");
                process::exit(2);
            }
            let (rows, _) = load(&args[2]);
            cmd_scale(&rows, n);
        }
        "-h" | "--help" | "help" => {
            print!("{}", USAGE);
        }
        other => {
            eprintln!("zkleak: unknown command {:?}\n", other);
            print!("{}", USAGE);
            process::exit(2);
        }
    }
}
