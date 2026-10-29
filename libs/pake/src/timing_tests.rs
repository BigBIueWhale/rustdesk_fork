//! R-P12 first-order timing evidence for one optimized Linux artifact.
//! Fixed budget; randomized classes; raw and pooled 99th-percentile Welch tests.
//! A passing observation is limited to these inputs, build and machine.

use super::{compute_tag, verify_tag, Scalar, Sha512, AD_RESPONDER};
use sha2::Digest;
use std::{hint::black_box, time::Instant};

const SAMPLES: usize = 1_000_000;
const BATCH: usize = 20_000;
const REPEATS: usize = 4;
const THRESHOLD: f64 = 10.0;

#[derive(Clone, Copy, Default)]
struct Moments {
    n: usize,
    mean: f64,
    m2: f64,
}

impl Moments {
    fn push(&mut self, value: f64) {
        self.n += 1;
        let delta = value - self.mean;
        self.mean += delta / self.n as f64;
        self.m2 += delta * (value - self.mean);
    }
}

fn welch(classes: &[Moments; 2]) -> f64 {
    let [a, b] = classes;
    assert!(a.n > 1 && b.n > 1);
    let variance = a.m2 / (a.n - 1) as f64 / a.n as f64
        + b.m2 / (b.n - 1) as f64 / b.n as f64;
    assert!(variance.is_finite() && variance > 0.0, "unusable timing variance");
    (a.mean - b.mean) / variance.sqrt()
}

// Reproducible non-secret sampling/shuffle input, outside the measured region.
fn random(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    value ^ (value >> 31)
}

#[inline(never)]
fn early_exit_compare(expected: &[u8; 64], candidate: &[u8; 64]) -> bool {
    for i in 0..64 {
        if black_box(expected[i]) != black_box(candidate[i]) {
            return false;
        }
    }
    true
}

fn measure<T>(
    name: &str,
    seed: u64,
    prepare: impl Fn(&mut [u8; 64], usize, &mut u64),
    execute: impl Fn(&[u8; 64]) -> T,
) -> bool {
    let mut state = seed;
    let mut inputs = vec![([0u8; 64], 0usize); BATCH];
    let mut observations = Vec::with_capacity(SAMPLES);
    let mut digest = Sha512::new();
    for batch in 0..=SAMPLES / BATCH {
        for (bytes, class) in &mut inputs {
            *class = (random(&mut state) >> 63) as usize;
            prepare(bytes, *class, &mut state);
            digest.update([*class as u8]);
            digest.update(*bytes);
        }
        for (bytes, class) in &inputs {
            let start = Instant::now();
            for _ in 0..REPEATS {
                black_box(execute(black_box(bytes)));
            }
            let elapsed = start.elapsed().as_nanos();
            assert!(elapsed > 0 && elapsed <= u64::MAX as u128);
            // The first batch warms code, allocation and input paths for both classes.
            if batch != 0 {
                observations.push((elapsed as u64, *class));
            }
        }
    }
    assert_eq!(observations.len(), SAMPLES);
    let mut durations: Vec<_> = observations.iter().map(|(ns, _)| *ns).collect();
    let cutoff_index = SAMPLES * 99 / 100;
    let (_, cutoff, _) = durations.select_nth_unstable(cutoff_index);
    let cutoff = *cutoff;
    let mut raw = [Moments::default(); 2];
    let mut cropped = raw;
    for (ns, class) in observations {
        raw[class].push(ns as f64);
        if ns <= cutoff {
            cropped[class].push(ns as f64);
        }
    }
    assert!(raw.iter().chain(cropped.iter()).all(|c| c.n >= SAMPLES * 45 / 100));
    let raw_t = welch(&raw);
    let cropped_t = welch(&cropped);
    assert!(raw_t.is_finite() && cropped_t.is_finite());
    let detected = raw_t.abs().max(cropped_t.abs()) > THRESHOLD;
    let input_sha512 = digest.finalize();
    let input_sha512: String = input_sha512.iter().map(|byte| format!("{byte:02x}")).collect();
    println!(
        "PAKE_TIMING_CASE=name:{name} seed:{seed:016x} samples:{SAMPLES} repeats:{REPEATS} \
         n0:{} n1:{} mean0_ns:{:.6} mean1_ns:{:.6} t_raw:{raw_t:.6} \
         cropped_n0:{} cropped_n1:{} cutoff_ns:{cutoff} t_p99:{cropped_t:.6} \
         threshold:{THRESHOLD} detected:{detected} input_sha512:{input_sha512}",
        raw[0].n, raw[1].n, raw[0].mean, raw[1].mean, cropped[0].n, cropped[1].n,
    );
    detected
}

#[test]
#[ignore = "requires the isolated optimized timing profile"]
fn optimized_timing_evidence() {
    assert!(!cfg!(debug_assertions), "timing requires an optimized build");
    // Arithmetic controls exercise the same estimator used for the measurements.
    let mut a = Moments::default();
    let mut b = Moments::default();
    for value in [1.0, 2.0, 3.0, 4.0] {
        a.push(value);
        b.push(value + 10.0);
    }
    assert!((welch(&[a, b]) + 10.0 / (5.0_f64 / 6.0).sqrt()).abs() < 1e-12);
    assert_eq!(welch(&[a, a]), 0.0);
    assert_eq!(welch(&[a, b]), -welch(&[b, a]));

    let key = [0x5au8; 64];
    let public_element = [0x42u8; 32];
    let expected = compute_tag(&key, &public_element, AD_RESPONDER);
    let mismatches = |bytes: &mut [u8; 64], class: usize, _: &mut u64| {
        *bytes = expected;
        bytes[if class == 0 { 0 } else { 63 }] ^= 1;
        assert!(!verify_tag(&key, &public_element, AD_RESPONDER, bytes));
    };
    let varied = |bytes: &mut [u8; 64], class: usize, state: &mut u64| {
        for chunk in bytes.chunks_exact_mut(8) {
            chunk.copy_from_slice(&random(state).to_le_bytes());
        }
        if class == 0 {
            bytes.fill(0);
        }
    };
    let control = measure("early-exit-first-last", 0x116f_3ec2_40ba_c981, mismatches,
        |bytes| early_exit_compare(black_box(&expected), bytes));
    let tag_position = measure("verify-tag-first-last", 0x7908_6dc5_183e_b2a4, mismatches,
        |bytes| verify_tag(black_box(&key), black_box(&public_element), AD_RESPONDER, bytes));
    let tag_key = measure("verify-tag-zero-random-key", 0xae25_634b_07d1_c89f, varied,
        |bytes| verify_tag(bytes, black_box(&public_element), AD_RESPONDER, black_box(&[0u8; 64])));
    // This is sample_scalar's wide-reduction primitive; OS RNG acquisition and
    // the complete sampling wrapper are outside this measured region.
    let scalar = measure("scalar-reduce-zero-random", 0x5c03_da94_f6b2_187e, varied,
        Scalar::from_bytes_mod_order_wide);
    assert!(control, "variable-time positive control was not detected: inconclusive");
    assert!(!tag_position && !tag_key && !scalar, "timing difference detected");
    println!("PAKE_TIMING_RESULT=no-difference-detected cohorts=3 positive_control=detected samples_per_cohort=1000000 repeats=4 statistic=welch-raw-and-pooled-p99 threshold=10 scope=linux-test-artifact");
}
