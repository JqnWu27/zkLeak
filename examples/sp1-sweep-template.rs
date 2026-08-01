//! Template: produce a zkleak CSV from your own SP1 guest.
//!
//! Copy into your SP1 project's `script/src/bin/`, adjust the three marked
//! places, and run. Uses `execute` only -- no proving -- so a full sweep costs
//! seconds per sample rather than minutes.
//!
//!   cargo run --release --bin sweep > leakage.csv
//!   zkleak report leakage.csv
//!
//! Dependencies (same as any SP1 script crate):
//!   sp1-sdk = "..."   matching your installed SP1 version
//!
//! API NOTE: SP1's SDK surface has changed across releases. This targets the
//! blocking client in recent versions:
//!     use sp1_sdk::{blocking::{Prover, ProverClient}, include_elf, Elf, SP1Stdin};
//! Older versions use `ProverClient::new()` and return `SP1Stdin` differently.
//! If it does not compile, check your version's docs for `execute` -- the only
//! thing this template needs is a cycle count per input.

use sp1_sdk::{
    blocking::{Prover, ProverClient},
    include_elf, Elf, SP1Stdin,
};

// (1) Point this at your guest's ELF.
const ELF: Elf = include_elf!("your-guest-program");

fn main() {
    let client = ProverClient::from_env();

    // CSV header. The optional third column is a prior weight; drop it if your
    // secret really is uniform, but real length distributions rarely are.
    println!("secret,cycles,weight");

    // (2) Sweep whatever your guest treats as SECRET. This example sweeps a
    //     message length from 1..=1024. Sweep the actual secret domain, not a
    //     convenient proxy -- coverage of the sweep bounds the validity of the
    //     result.
    for len in 1u32..=1024 {
        let mut stdin = SP1Stdin::new();

        // (3) Write inputs exactly as your guest reads them. IMPORTANT: keep
        //     every *public* input fixed across the sweep, and keep the input
        //     SIZE fixed too. If the buffer you write grows with `len`, you are
        //     measuring input-size leakage confounded with trace-length
        //     leakage, and cannot tell which one you found.
        let payload = vec![0u8; 1024]; // fixed size, always
        stdin.write(&len); // the secret
        stdin.write_vec(payload);

        let (_public_values, report) = client
            .execute(ELF, stdin)
            .run()
            .expect("execute failed");

        let cycles = report.total_instruction_count();

        // Prior weight for this secret. Uniform = 1.0. For a skewed length
        // distribution, put your empirical frequency here instead.
        let weight = 1.0f64;

        println!("{},{},{}", len, cycles, weight);

        if len % 128 == 0 {
            eprintln!("  {} / 1024", len);
        }
    }
}
