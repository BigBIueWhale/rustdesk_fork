//! R-P12 first-order timing evidence for one optimized Linux artifact.
//! Fixed budget; randomized classes; raw and pooled 99th-percentile Welch tests.
//! A passing observation is limited to these inputs, build and machine.

use super::{channel_identifier, compute_tag, derive_generator, verify_tag, RistrettoPoint,
    Scalar, Sha512, Zeroizing, AD_RESPONDER, CI_PORT};
use sha2::Digest;
use std::{arch::{asm, x86_64::__cpuid_count}, hint::black_box, marker::PhantomData, time::Instant};

const SAMPLES: usize = 1_000_000;
const GROUP_SAMPLES: usize = 100_000;
const BATCH: usize = 20_000;
const REPEATS: usize = 4;
const THRESHOLD: f64 = 10.0;

fn read_mxcsr() -> u32 {
    let mut value = 0u32;
    // SAFETY: x86-64 provides SSE; STMXCSR writes exactly this live u32.
    unsafe { asm!("stmxcsr [{value}]", value = in(reg) &mut value, options(nostack, preserves_flags)); }
    value
}

// Test-thread-only diagnostic: change status flags, never Rust's floating-point
// masks, rounding mode, DAZ or FTZ. Restore on return and unwind on this thread.
struct McdtStatusScope {
    saved: u32,
    _thread: PhantomData<*mut ()>,
}

impl McdtStatusScope {
    #[inline(never)]
    fn enter() -> Self {
        let saved = read_mxcsr();
        assert_eq!(saved & !0x3f, 0x1f80, "nondefault MXCSR controls");
        let value = saved | 0x3f;
        let scope = Self { saved, _thread: PhantomData };
        // SAFETY: only the six status flags differ from a valid observed value;
        // controls stay at Rust defaults. Memory is live and fences serialize
        // the change. No preserves_flags promise is made for this write.
        unsafe { asm!("lfence", "ldmxcsr [{value}]", "lfence",
            value = in(reg) &value, options(nostack)); }
        scope
    }
}

impl Drop for McdtStatusScope {
    #[inline(never)]
    fn drop(&mut self) {
        // SAFETY: saved was read on this thread with default controls; the guard
        // cannot be sent to another thread. Only status flags were modified.
        unsafe { asm!("lfence", "ldmxcsr [{value}]", "lfence",
            value = in(reg) &self.saved, options(nostack)); }
    }
}

fn check_mxcsr_scope() {
    let before = read_mxcsr();
    {
        let _scope = McdtStatusScope::enter();
        assert_eq!(read_mxcsr(), 0x1fbf);
    }
    assert_eq!(read_mxcsr(), before);
    let unwind = std::panic::catch_unwind(|| -> () {
        let _scope = McdtStatusScope::enter();
        assert_eq!(read_mxcsr(), 0x1fbf);
        std::panic::resume_unwind(Box::new(()));
    });
    assert!(unwind.expect_err("diagnostic did not unwind").is::<()>());
    assert_eq!(read_mxcsr(), before);
    // SAFETY: CPUID is available on x86-64; query supported leaves/subleaves.
    let (leaf1, leaf7, mcdt) = unsafe {
        assert!(__cpuid_count(0, 0).eax >= 7);
        let leaf1 = __cpuid_count(1, 0);
        let leaf7 = __cpuid_count(7, 0);
        let mcdt = (leaf7.eax >= 2).then(|| __cpuid_count(7, 2).edx);
        (leaf1, leaf7, mcdt)
    };
    println!("PAKE_TIMING_MXCSR_SCOPE=pass normal_restore=true unwind_restore=true initial={before:08x} controls=00001f80 configured=00001fbf cpuid1_eax={:08x} hypervisor={} leaf7_max_subleaf={} leaf7_2_edx={mcdt:?} mcdt_no={:?} avx2_available={}",
        leaf1.eax, leaf1.ecx >> 31, leaf7.eax, mcdt.map(|value| value & (1 << 5) != 0),
        std::is_x86_feature_detected!("avx2"));
}

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

fn varied(bytes: &mut [u8; 64], class: usize, state: &mut u64) {
    for chunk in bytes.chunks_exact_mut(8) {
        chunk.copy_from_slice(&random(state).to_le_bytes());
    }
    if class == 0 {
        bytes.fill(0);
    }
}

fn scalar_inputs(bytes: &mut [u8; 64], class: usize, state: &mut u64) {
    varied(bytes, class, state);
    if class == 0 {
        bytes[0] = 1;
    }
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
    samples: usize,
    prepare: impl Fn(&mut [u8; 64], usize, &mut u64),
    execute: impl Fn(&[u8; 64]) -> T,
) -> bool {
    measure_prepared(name, seed, samples, prepare, |bytes| *bytes, execute)
}

fn measure_prepared<I, T>(
    name: &str,
    seed: u64,
    samples: usize,
    prepare: impl Fn(&mut [u8; 64], usize, &mut u64),
    decode: impl Fn(&[u8; 64]) -> I,
    execute: impl Fn(&I) -> T,
) -> bool {
    assert!(samples >= BATCH && samples % BATCH == 0);
    let mut state = seed;
    let mut inputs = vec![([0u8; 64], 0usize); BATCH];
    let mut observations = Vec::with_capacity(samples);
    let mut digest = Sha512::new();
    let mxcsr_begin = read_mxcsr();
    for batch in 0..=samples / BATCH {
        for (bytes, class) in &mut inputs {
            *class = (random(&mut state) >> 63) as usize;
            prepare(bytes, *class, &mut state);
            digest.update([*class as u8]);
            digest.update(*bytes);
        }
        // Decode the entire batch before timing so reduction or point creation
        // can be excluded without changing the label stream or source inputs.
        let prepared: Vec<_> = inputs.iter().map(|(bytes, class)| (decode(bytes), *class)).collect();
        for (input, class) in &prepared {
            let start = Instant::now();
            for _ in 0..REPEATS {
                black_box(execute(black_box(input)));
            }
            let elapsed = start.elapsed().as_nanos();
            assert!(elapsed > 0 && elapsed <= u64::MAX as u128);
            // The first batch warms code, allocation and input paths for both classes.
            if batch != 0 {
                observations.push((elapsed as u64, *class));
            }
        }
    }
    let mxcsr_end = read_mxcsr();
    assert_eq!(observations.len(), samples);
    let mut durations: Vec<_> = observations.iter().map(|(ns, _)| *ns).collect();
    let cutoff_index = samples * 99 / 100;
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
    assert!(raw.iter().chain(cropped.iter()).all(|c| c.n >= samples * 45 / 100));
    let raw_t = welch(&raw);
    let cropped_t = welch(&cropped);
    assert!(raw_t.is_finite() && cropped_t.is_finite());
    let detected = raw_t.abs().max(cropped_t.abs()) > THRESHOLD;
    let input_sha512 = digest.finalize();
    let input_sha512: String = input_sha512.iter().map(|byte| format!("{byte:02x}")).collect();
    println!(
        "PAKE_TIMING_CASE=name:{name} seed:{seed:016x} samples:{samples} repeats:{REPEATS} \
         n0:{} n1:{} mean0_ns:{:.6} mean1_ns:{:.6} t_raw:{raw_t:.6} \
         cropped_n0:{} cropped_n1:{} cutoff_ns:{cutoff} t_p99:{cropped_t:.6} \
         threshold:{THRESHOLD} detected:{detected} input_sha512:{input_sha512} \
         mxcsr_begin:{mxcsr_begin:08x} mxcsr_end:{mxcsr_end:08x}",
        raw[0].n, raw[1].n, raw[0].mean, raw[1].mean, cropped[0].n, cropped[1].n,
    );
    detected
}

#[test]
#[ignore = "requires the isolated optimized timing profile"]
fn optimized_timing_evidence() {
    assert!(!cfg!(debug_assertions), "timing requires an optimized build");
    check_mxcsr_scope();
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
    let control = measure("early-exit-first-last", 0x116f_3ec2_40ba_c981, SAMPLES, mismatches,
        |bytes| early_exit_compare(black_box(&expected), bytes));
    let tag_position = measure("verify-tag-first-last", 0x7908_6dc5_183e_b2a4, SAMPLES, mismatches,
        |bytes| verify_tag(black_box(&key), black_box(&public_element), AD_RESPONDER, bytes));
    let tag_key = measure("verify-tag-zero-random-key", 0xae25_634b_07d1_c89f, SAMPLES, varied,
        |bytes| verify_tag(bytes, black_box(&public_element), AD_RESPONDER, black_box(&[0u8; 64])));
    // This is sample_scalar's wide-reduction primitive; OS RNG acquisition and
    // the complete sampling wrapper are outside this measured region.
    let scalar = measure("scalar-reduce-zero-random", 0x5c03_da94_f6b2_187e, SAMPLES, varied,
        Scalar::from_bytes_mod_order_wide);

    // The production PRS is a 44-byte canonical base64 encoding of 32 bytes.
    // Both classes retain that public length/encoding; preparation is untimed.
    let prs_inputs = |bytes: &mut [u8; 64], class: usize, state: &mut u64| {
        const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        bytes.fill(0);
        for byte in &mut bytes[..42] {
            *byte = ALPHABET[(random(state) & 63) as usize];
        }
        bytes[42] = ALPHABET[((random(state) & 15) << 2) as usize];
        if class == 0 {
            bytes[..43].fill(b'A');
        }
        bytes[43] = b'=';
    };
    let ci = channel_identifier(CI_PORT);
    let sid = [0x62u8; 32];
    let generator = measure("generator-fixed-random-prs", 0xb279_41d0_6c85_3efa,
        GROUP_SAMPLES, prs_inputs,
        |bytes| derive_generator(&bytes[..44], black_box(&ci), black_box(&sid)));

    let mut fixed_prs = [b'A'; 44];
    fixed_prs[43] = b'=';
    let point = derive_generator(&fixed_prs, &ci, &sid);
    // The deliberate variable-time control computes the same group result.
    // Only this test uses it; production uses the ordinary multiplication operator.
    for scalar in [Scalar::ONE, Scalar::from_bytes_mod_order_wide(&[0x63; 64])] {
        assert_eq!((&scalar * &*point).compress(),
            RistrettoPoint::vartime_double_scalar_mul_basepoint(&scalar, &point, &Scalar::ZERO).compress());
    }
    let group_control = measure("vartime-multiply-one-random", 0x4a16_c09e_72f3_b85d,
        GROUP_SAMPLES, scalar_inputs, |bytes| {
            let scalar = Zeroizing::new(Scalar::from_bytes_mod_order_wide(bytes));
            Zeroizing::new(RistrettoPoint::vartime_double_scalar_mul_basepoint(
                &scalar, black_box(&point), black_box(&Scalar::ZERO)))
        });
    // Includes wide reduction, variable-base multiplication and wiping owners;
    // excludes OS RNG and point preparation. The fixed point is not a base table.
    let multiply = |bytes: &[u8; 64]| {
        let scalar = Zeroizing::new(Scalar::from_bytes_mod_order_wide(bytes));
        Zeroizing::new(&*scalar * black_box(&*point))
    };
    let multiplication = measure("reduce-multiply-one-random", 0x8d02_57be_a913_c64f,
        GROUP_SAMPLES, scalar_inputs, multiply);
    // Keep the same label stream and execution closure. Reversal tests whether
    // a difference follows input values; identical inputs check label bias.
    let reversed = measure("reduce-multiply-random-one", 0x8d02_57be_a913_c64f,
        GROUP_SAMPLES, |bytes, class, state| scalar_inputs(bytes, class ^ 1, state), multiply);
    let identical = measure("reduce-multiply-one-one", 0x8d02_57be_a913_c64f,
        GROUP_SAMPLES, |bytes, _, state| scalar_inputs(bytes, 0, state), multiply);

    // Separate the composed operation's costs. These are public test fixtures;
    // the unguarded multiplication below changes no production secret owner.
    let prepared_control = measure_prepared("vartime-prepared-one-random", 0x4a16_c09e_72f3_b85d,
        GROUP_SAMPLES, scalar_inputs, Scalar::from_bytes_mod_order_wide,
        |scalar| RistrettoPoint::vartime_double_scalar_mul_basepoint(
            scalar, black_box(&point), black_box(&Scalar::ZERO)));
    let mut component_differences = [false; 3];
    let mut component_identical = [false; 3];
    for (orientation, suffix) in ["one-random", "random-one", "one-one"].iter().enumerate() {
        let inputs = |bytes: &mut [u8; 64], class: usize, state: &mut u64| {
            let class = match orientation {
                0 => class,
                1 => class ^ 1,
                _ => 0,
            };
            scalar_inputs(bytes, class, state);
        };
        let reduction = measure(&format!("reduce-wipe-{suffix}"), 0x8d02_57be_a913_c64f,
            GROUP_SAMPLES, inputs,
            |bytes| Zeroizing::new(Scalar::from_bytes_mod_order_wide(bytes)));
        let arithmetic = measure_prepared(&format!("multiply-prepared-{suffix}"), 0x8d02_57be_a913_c64f,
            GROUP_SAMPLES, inputs, Scalar::from_bytes_mod_order_wide,
            |scalar| scalar * black_box(&*point));
        // Copy and wipe the actual multiplication result, prepared outside the
        // clock. This measures that owner's cost, not post-drop erasure coverage.
        let cleanup = measure_prepared(&format!("point-copy-wipe-{suffix}"), 0x8d02_57be_a913_c64f,
            GROUP_SAMPLES, inputs, |bytes| &Scalar::from_bytes_mod_order_wide(bytes) * &*point,
            |prepared_point| Zeroizing::new(*prepared_point));
        let differences = [reduction, arithmetic, cleanup];
        if orientation == 2 {
            component_identical = differences;
        } else {
            for (detected, difference) in component_differences.iter_mut().zip(differences) {
                *detected |= difference;
            }
        }
    }
    let before_mcdt = read_mxcsr();
    let (mcdt_control, mcdt_multiply, mcdt_reversed, mcdt_identical) = {
        let _scope = McdtStatusScope::enter();
        assert_eq!(read_mxcsr(), 0x1fbf);
        let control = measure_prepared("vartime-mcdt-one-random", 0x4a16_c09e_72f3_b85d,
            GROUP_SAMPLES, scalar_inputs, Scalar::from_bytes_mod_order_wide,
            |scalar| RistrettoPoint::vartime_double_scalar_mul_basepoint(
                scalar, black_box(&point), black_box(&Scalar::ZERO)));
        let multiply = |scalar: &Scalar| scalar * black_box(&*point);
        let ordinary = measure_prepared("multiply-mcdt-one-random", 0x8d02_57be_a913_c64f,
            GROUP_SAMPLES, scalar_inputs, Scalar::from_bytes_mod_order_wide, multiply);
        let reversed = measure_prepared("multiply-mcdt-random-one", 0x8d02_57be_a913_c64f,
            GROUP_SAMPLES, |bytes, class, state| scalar_inputs(bytes, class ^ 1, state),
            Scalar::from_bytes_mod_order_wide, multiply);
        let identical = measure_prepared("multiply-mcdt-one-one", 0x8d02_57be_a913_c64f,
            GROUP_SAMPLES, |bytes, _, state| scalar_inputs(bytes, 0, state),
            Scalar::from_bytes_mod_order_wide, multiply);
        assert_eq!(read_mxcsr(), 0x1fbf);
        (control, ordinary, reversed, identical)
    };
    assert_eq!(read_mxcsr(), before_mcdt);
    println!("PAKE_TIMING_MXCSR_RESTORED=value:{before_mcdt:08x}");
    let restored = measure_prepared("multiply-restored-one-random", 0x8d02_57be_a913_c64f,
        GROUP_SAMPLES, scalar_inputs, Scalar::from_bytes_mod_order_wide,
        |scalar| scalar * black_box(&*point));

    assert!(control && group_control && prepared_control && mcdt_control,
        "variable-time positive control was not detected: inconclusive");
    assert!(!identical && !mcdt_identical && !component_identical.iter().any(|detected| *detected),
        "identical-input negative control detected a difference: inconclusive");
    assert!(!tag_position && !tag_key && !scalar && !generator && !multiplication && !reversed,
        "timing difference detected");
    assert!(!component_differences.iter().any(|detected| *detected),
        "component timing difference detected");
    assert!(!mcdt_multiply && !mcdt_reversed && !restored, "MXCSR comparison timing difference detected");
    println!("PAKE_TIMING_RESULT=no-difference-detected cohorts=15 positive_controls=4 negative_controls=5 primitive_samples=1000000 group_samples=100000 repeats=4 statistic=welch-raw-and-pooled-p99 threshold=10 scope=linux-test-artifact");
}

#[test]
#[ignore = "requires the isolated optimized backend comparison"]
fn backend_timing_evidence() {
    assert!(!cfg!(debug_assertions), "timing requires an optimized build");
    check_mxcsr_scope();
    let mut prs = [b'A'; 44];
    prs[43] = b'=';
    let point = derive_generator(&prs, &channel_identifier(CI_PORT), &[0x62; 32]);
    let control = measure_prepared("vartime-prepared-one-random", 0x4a16_c09e_72f3_b85d,
        GROUP_SAMPLES, scalar_inputs, Scalar::from_bytes_mod_order_wide,
        |scalar| RistrettoPoint::vartime_double_scalar_mul_basepoint(
            scalar, black_box(&point), black_box(&Scalar::ZERO)));
    let mut detected = [false; 3];
    for (orientation, suffix) in ["one-random", "random-one", "one-one"].iter().enumerate() {
        detected[orientation] = measure_prepared(&format!("multiply-prepared-{suffix}"),
            0x8d02_57be_a913_c64f, GROUP_SAMPLES, |bytes, class, state| {
                let class = match orientation { 0 => class, 1 => class ^ 1, _ => 0 };
                scalar_inputs(bytes, class, state);
            }, Scalar::from_bytes_mod_order_wide, |scalar| scalar * black_box(&*point));
    }
    assert!(control, "variable-time positive control was not detected: inconclusive");
    assert!(!detected[2], "identical-input negative control detected a difference: inconclusive");
    assert!(!detected[..2].iter().any(|value| *value), "backend timing difference detected");
    println!("PAKE_TIMING_BACKEND_RESULT=no-difference-detected cohorts=2 positive_controls=1 negative_controls=1 samples=100000 repeats=4 statistic=welch-raw-and-pooled-p99 threshold=10 scope=linux-test-artifact");
}
