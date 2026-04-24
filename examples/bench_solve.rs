//! Timed benchmark of `EquixEngine::solve_bundle`.
//!
//! Env vars (all optional):
//!   BITS=7 THREADS=3 REQUIRED=30 SAMPLES=30 WARMUP=1
//!
//! Emits one `sample,<idx>,elapsed_ms,<ms>` line per run (to stdout) and a
//! final stats line on stderr. Stdout is machine-parsable CSV-ish; stderr is
//! human summary.

use rspow::equix::EquixEngineBuilder;
use rspow::pow::{PowBundle, PowEngine};
use std::env;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let bits: u32 = env_parse("BITS", 7);
    let threads: usize = env_parse("THREADS", 3);
    let required: usize = env_parse("REQUIRED", 30);
    let samples: usize = env_parse("SAMPLES", 30);
    let warmup: usize = env_parse("WARMUP", 1);

    eprintln!(
        "config: bits={} threads={} required_proofs={} samples={} warmup={}",
        bits, threads, required, samples, warmup
    );

    // Warmup (ignored).
    for i in 0..warmup {
        let progress = Arc::new(AtomicU64::new(0));
        let mut engine = EquixEngineBuilder::default()
            .bits(bits)
            .threads(threads)
            .required_proofs(required)
            .progress(progress)
            .build_validated()
            .expect("valid config");
        let master = [(0xA0 + i as u8); 32];
        let _ = engine.solve_bundle(master).expect("warmup solve");
    }

    let mut timings_s: Vec<f64> = Vec::with_capacity(samples);
    for i in 0..samples {
        let progress = Arc::new(AtomicU64::new(0));
        let mut engine = EquixEngineBuilder::default()
            .bits(bits)
            .threads(threads)
            .required_proofs(required)
            .progress(progress)
            .build_validated()
            .expect("valid config");
        let master = [i as u8; 32];
        let start = Instant::now();
        let bundle = engine.solve_bundle(master).expect("solve should succeed");
        let elapsed = start.elapsed();
        let ms = elapsed.as_secs_f64() * 1000.0;
        println!(
            "sample,{},elapsed_ms,{:.3},proofs,{}",
            i,
            ms,
            bundle.proofs().len()
        );
        timings_s.push(elapsed.as_secs_f64());
    }

    let n = timings_s.len() as f64;
    if n == 0.0 {
        eprintln!("no samples collected");
        return;
    }
    let mean = timings_s.iter().sum::<f64>() / n;
    let variance = if n > 1.0 {
        timings_s.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0)
    } else {
        0.0
    };
    let stdev = variance.sqrt();
    let se = if n > 1.0 { stdev / n.sqrt() } else { 0.0 };
    let ci95 = 1.96 * se;

    let mut sorted = timings_s.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let min = *sorted.first().unwrap();
    let max = *sorted.last().unwrap();
    let median = sorted[sorted.len() / 2];

    eprintln!(
        "stats n={} mean={:.3}s ±{:.3}s (95%% CI) stdev={:.3}s min={:.3}s median={:.3}s max={:.3}s",
        samples, mean, ci95, stdev, min, median, max
    );
}
