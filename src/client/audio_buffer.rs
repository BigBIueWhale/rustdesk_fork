use hbb_common::log;
use ringbuf::{ring_buffer::RbBase, Rb};
use std::{
    sync::{Arc, Mutex, TryLockError},
    time::{Duration, Instant},
};

pub const AUDIO_BUFFER_MS: usize = 3000;
const SHRINK_INTERVAL: Duration = Duration::from_secs(12);

pub(super) struct AudioBuffer {
    pub(super) samples: Arc<Mutex<ringbuf::HeapRb<f32>>>,
    sample_rate_channels: usize,
    channels: usize,
    occupancy_samples: [usize; 30],
    last_shrink: Option<Instant>,
}

impl AudioBuffer {
    pub(super) fn new(sample_rate: usize, channels: usize) -> std::io::Result<Self> {
        let invalid_geometry = || std::io::Error::from(std::io::ErrorKind::InvalidInput);
        let sample_rate_channels = sample_rate.checked_mul(channels)
            .filter(|&samples| samples > 0).ok_or_else(invalid_geometry)?;
        let capacity = sample_rate_channels.checked_mul(AUDIO_BUFFER_MS)
            .map(|samples| samples / 1000)
            .filter(|&samples| samples > 0
                && samples <= isize::MAX as usize / std::mem::size_of::<f32>())
            .ok_or_else(invalid_geometry)?;
        let samples = ringbuf::HeapRb::<f32>::try_new(capacity)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
        Ok(Self {
            samples: Arc::new(Mutex::new(samples)),
            sample_rate_channels,
            channels,
            occupancy_samples: [0; 30],
            last_shrink: None,
        })
    }

    fn try_shrink(&mut self, having: usize, now: Instant) {
        let mut i = (having * 10) / self.sample_rate_channels;
        if i > 29 {
            i = 29;
        }
        self.occupancy_samples[i] += 1;

        let Some(last_shrink) = self.last_shrink else {
            self.last_shrink = Some(now);
            return;
        };
        let Some(elapsed) = now.checked_duration_since(last_shrink) else {
            log::warn!("audio shrink clock moved backwards; restarting its observation window");
            self.occupancy_samples = [0; 30];
            self.occupancy_samples[i] = 1;
            self.last_shrink = Some(now);
            return;
        };
        if elapsed < SHRINK_INTERVAL {
            return;
        }
        self.last_shrink = Some(now);

        // the safer water mark to drop
        let mut zero = 0;
        // the water mark taking most of time
        let mut max = 0;
        for i in 0..30 {
            if self.occupancy_samples[i] == 0 && zero == i {
                zero += 1;
            }

            if self.occupancy_samples[i] > self.occupancy_samples[max] {
                self.occupancy_samples[max] = 0;
                max = i;
            } else {
                self.occupancy_samples[i] = 0;
            }
        }
        zero = zero * 2 / 3;

        // how many data can be dropped:
        // 1. will not drop if buffered data is less than 600ms
        // 2. choose based on min(zero, max)
        const N: usize = 4;
        self.occupancy_samples[max] = 0;
        if max < 6 {
            return;
        } else if max > zero * N {
            max = zero * N;
        }

        let mut lock = self.samples.lock().unwrap();
        let cap = lock.capacity();
        let having = lock.occupied_len();
        let skip = (cap * max / (30 * N)).div_ceil(self.channels) * self.channels;
        if (having > skip * 3) && (skip > 0) {
            lock.skip(skip);
            log::info!("skip {skip}, based {max} {zero}");
        }
    }

    /// append pcm to audio buffer, if buffered data
    /// exceeds AUDIO_BUFFER_MS,  only AUDIO_BUFFER_MS
    /// will be kept.
    fn append_pcm2(&self, buffer: &[f32]) -> usize {
        let mut lock = self.samples.lock().unwrap();
        let cap = lock.capacity();
        if buffer.len() > cap {
            lock.push_slice_overwrite(buffer);
            return cap;
        }

        let having = lock.occupied_len() + buffer.len();
        if having > cap {
            lock.skip(having - cap);
        }
        lock.push_slice_overwrite(buffer);
        lock.occupied_len()
    }

    /// append pcm to audio buffer, trying to drop data
    /// when data is too much (per 12 seconds) based
    /// statistics.
    pub(super) fn append_pcm(&mut self, buffer: &[f32]) {
        let having = self.append_pcm2(buffer);
        self.try_shrink(having, Instant::now());
    }
}

pub(super) fn fill_output<T>(
    samples: &Mutex<ringbuf::HeapRb<f32>>,
    output: &mut [T],
    convert: fn(f32) -> T,
) {
    let mut samples = match samples.try_lock() {
        Ok(samples) => Some(samples),
        Err(TryLockError::WouldBlock) => None,
        Err(TryLockError::Poisoned(error)) => panic!("audio PCM ring was poisoned: {error}"),
    };
    for output in output {
        let sample = samples
            .as_mut()
            .and_then(|samples| samples.pop())
            .unwrap_or(0.);
        *output = convert(sample);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_buffer() -> AudioBuffer {
        let mut buffer = AudioBuffer::new(4, 1).unwrap();
        assert_eq!(buffer.append_pcm2(&[0., 1., 2., 3., 4., 5., 6., 7.]), 8);
        buffer
    }

    fn queued(buffer: &AudioBuffer) -> usize {
        buffer.samples.lock().unwrap().occupied_len()
    }

    #[test]
    fn first_observation_arms_only_its_own_window() {
        let start = Instant::now();
        let mut buffer = full_buffer();
        buffer.try_shrink(8, start);
        assert_eq!(buffer.last_shrink, Some(start));
        assert_eq!(queued(&buffer), 8);
        assert_eq!(buffer.occupancy_samples[20], 1);
    }

    #[test]
    fn exact_interval_trims_without_early_retirement() {
        let start = Instant::now();
        let mut buffer = full_buffer();
        buffer.try_shrink(8, start);
        buffer.try_shrink(8, start + SHRINK_INTERVAL - Duration::from_nanos(1));
        assert_eq!(buffer.last_shrink, Some(start));
        assert_eq!(queued(&buffer), 8);
        buffer.try_shrink(8, start + SHRINK_INTERVAL);
        assert_eq!(buffer.last_shrink, Some(start + SHRINK_INTERVAL));
        assert_eq!(queued(&buffer), 6);
        assert!(buffer.occupancy_samples.iter().all(|&count| count == 0));
        let mut samples = [0.; 6];
        buffer.samples.lock().unwrap().pop_slice(&mut samples);
        assert_eq!(samples, [2., 3., 4., 5., 6., 7.]);
    }

    #[test]
    fn independently_started_buffers_do_not_postpone_each_other() {
        let start = Instant::now();
        let mut first = full_buffer();
        let mut second = full_buffer();
        first.try_shrink(8, start);
        second.try_shrink(8, start + Duration::from_secs(5));
        first.try_shrink(8, start + SHRINK_INTERVAL);
        second.try_shrink(8, start + SHRINK_INTERVAL);
        assert_eq!((queued(&first), queued(&second)), (6, 8));
        assert_eq!(second.last_shrink, Some(start + Duration::from_secs(5)));
        second.try_shrink(8, start + Duration::from_secs(5) + SHRINK_INTERVAL);
        assert_eq!(queued(&second), 6);
        assert_eq!(first.last_shrink, Some(start + SHRINK_INTERVAL));
    }

    #[test]
    fn backwards_clock_preserves_pcm_and_restarts_observation() {
        let start = Instant::now();
        let mut buffer = full_buffer();
        buffer.try_shrink(8, start + Duration::from_secs(1));
        buffer.try_shrink(8, start);
        assert_eq!(queued(&buffer), 8);
        assert_eq!(buffer.last_shrink, Some(start));
        assert_eq!(buffer.occupancy_samples.iter().sum::<usize>(), 1);
        buffer.try_shrink(8, start + SHRINK_INTERVAL);
        assert_eq!(queued(&buffer), 6);
    }

    #[test]
    fn ring_replacement_retires_old_statistics_and_clock() {
        let start = Instant::now();
        let mut buffer = full_buffer();
        buffer.try_shrink(8, start);
        buffer = AudioBuffer::new(8, 1).unwrap();
        assert_eq!(queued(&buffer), 0);
        assert_eq!(buffer.last_shrink, None);
        assert!(buffer.occupancy_samples.iter().all(|&count| count == 0));
        assert_eq!(buffer.append_pcm2(&[1.; 16]), 16);
        buffer.try_shrink(16, start + SHRINK_INTERVAL);
        assert_eq!(buffer.last_shrink, Some(start + SHRINK_INTERVAL));
        assert_eq!(queued(&buffer), 16);
    }

    #[test]
    fn equal_format_buffers_keep_independent_observation_windows() {
        let start = Instant::now();
        let mut buffer = full_buffer();
        buffer.try_shrink(8, start);
        let other = AudioBuffer::new(4, 1).unwrap();
        assert!(!Arc::ptr_eq(&buffer.samples, &other.samples));
        assert_eq!(queued(&other), 0);
        assert_eq!(other.last_shrink, None);
        assert_eq!(queued(&buffer), 8);
        assert_eq!(buffer.last_shrink, Some(start));
        assert_eq!(buffer.occupancy_samples[20], 1);
    }

    #[test]
    fn trimming_preserves_complete_interleaved_frames() {
        for sample_rate in [44100, 48000] {
            for channels in 1..=8 {
                let mut buffer = AudioBuffer::new(sample_rate, channels).unwrap();
                let capacity = buffer.samples.lock().unwrap().capacity();
                let input: Vec<f32> = (0..capacity)
                    .map(|index| (index % channels) as f32)
                    .collect();
                assert_eq!(buffer.append_pcm2(&input), capacity);
                let start = Instant::now();
                buffer.try_shrink(capacity, start);
                buffer.try_shrink(capacity, start + SHRINK_INTERVAL);
                let retained = queued(&buffer);
                let dropped = capacity - retained;
                println!(
                    "AUDIO_FRAME_ALIGNMENT=observed rate={sample_rate} channels={channels} dropped={dropped} retained={retained}"
                );
                assert!(dropped > 0 && retained > 0);
                assert_eq!(dropped % channels, 0, "trim split an interleaved frame");
                assert_eq!(retained % channels, 0);
                let mut output = vec![-1.; retained];
                fill_output(&buffer.samples, &mut output, |sample| sample);
                assert!(output
                    .iter()
                    .enumerate()
                    .all(|(index, &sample)| sample == (index % channels) as f32));
                assert_eq!(queued(&buffer), 0);
            }
        }
        println!("AUDIO_FRAME_ALIGNMENT=pass formats=16 rates=44100,48000 channels=1-8");
    }

    #[test]
    fn same_capacity_channel_change_retires_pcm() {
        let mut buffer = AudioBuffer::new(48000, 2).unwrap();
        let capacity = buffer.samples.lock().unwrap().capacity();
        assert_eq!(buffer.append_pcm2(&[1., 2., 3., 4.]), 4);
        buffer.try_shrink(4, Instant::now());
        buffer = AudioBuffer::new(96000, 1).unwrap();
        assert_eq!(buffer.samples.lock().unwrap().capacity(), capacity);
        println!(
            "AUDIO_GEOMETRY_RESET=observed old_rate=48000 old_channels=2 rate=96000 channels=1 capacity={capacity} queued={} observations={} clock_armed={}",
            queued(&buffer),
            buffer.occupancy_samples.iter().sum::<usize>(),
            buffer.last_shrink.is_some(),
        );
        assert_eq!(queued(&buffer), 0);
        assert_eq!(buffer.last_shrink, None);
        assert!(buffer.occupancy_samples.iter().all(|&count| count == 0));
        assert_eq!(buffer.append_pcm2(&[9.]), 1);
        let mut output = [-1.; 2];
        fill_output(&buffer.samples, &mut output, |sample| sample);
        assert_eq!(output, [9., 0.]);
        println!("AUDIO_GEOMETRY_RESET=pass same_capacity=true old_pcm=retired statistics=retired clock=retired new_pcm=preserved");
    }

    #[test]
    fn bounded_append_preserves_the_newest_pcm() {
        let mut buffer = AudioBuffer::new(4, 1).unwrap();
        buffer.append_pcm(&[0., 1., 2., 3., 4., 5., 6., 7., 8., 9.]);
        buffer.append_pcm(&[10., 11., 12., 13.]);
        assert_eq!(queued(&buffer), 12);
        let mut samples = [0.; 12];
        buffer.samples.lock().unwrap().pop_slice(&mut samples);
        assert_eq!(samples, [2., 3., 4., 5., 6., 7., 8., 9., 10., 11., 12., 13.]);
        buffer.append_pcm(&[9.; 20]);
        assert_eq!(queued(&buffer), 12);
        buffer.samples.lock().unwrap().pop_slice(&mut samples);
        assert_eq!(samples, [9.; 12]);
    }

    #[test]
    fn parallel_native_workers_keep_distinct_clock_epochs() {
        let start = Instant::now();
        let barrier = Arc::new(std::sync::Barrier::new(4));
        let mut workers = Vec::new();
        for index in 0..4 {
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                let mut buffer = full_buffer();
                let epoch = start + Duration::from_secs(index);
                buffer.try_shrink(8, epoch);
                barrier.wait();
                for period in 1..=200 {
                    buffer.try_shrink(8, epoch + SHRINK_INTERVAL * period);
                    assert_eq!(buffer.last_shrink, Some(epoch + SHRINK_INTERVAL * period));
                    assert_eq!(queued(&buffer), 6);
                    assert_eq!(buffer.append_pcm2(&[6., 7.]), 8);
                }
                buffer.last_shrink
            }));
        }
        for (index, worker) in workers.into_iter().enumerate() {
            assert_eq!(
                worker.join().unwrap(),
                Some(start + Duration::from_secs(index as u64) + SHRINK_INTERVAL * 200)
            );
        }
    }

    #[test]
    fn output_fill_consumes_fifo_and_pads_a_short_quantum() {
        let mut buffer = AudioBuffer::new(4, 1).unwrap();
        buffer.append_pcm2(&[0.5, -0.25, 0.75]);
        let mut output = [9.; 5];
        fill_output(&buffer.samples, &mut output, |sample| sample);
        assert_eq!(output, [0.5, -0.25, 0.75, 0., 0.]);
        assert_eq!(queued(&buffer), 0);
    }

    #[test]
    fn empty_output_fill_is_all_silence() {
        let buffer = AudioBuffer::new(48000, 2).unwrap();
        let mut output = [9.; 64];
        fill_output(&buffer.samples, &mut output, |sample| sample);
        assert_eq!(output, [0.; 64]);
    }

    #[test]
    fn output_fill_preserves_next_quantum_order() {
        let buffer = full_buffer();
        let mut empty = [];
        fill_output(&buffer.samples, &mut empty, |_| -> f32 {
            panic!("empty output converted")
        });
        assert_eq!(queued(&buffer), 8);
        let mut first = [9.; 3];
        let mut second = [9.; 5];
        fill_output(&buffer.samples, &mut first, |sample| sample);
        fill_output(&buffer.samples, &mut second, |sample| sample);
        assert_eq!(first, [0., 1., 2.]);
        assert_eq!(second, [3., 4., 5., 6., 7.]);
        assert_eq!(queued(&buffer), 0);
    }

    #[test]
    fn output_fill_passes_silence_through_the_converter() {
        let mut buffer = AudioBuffer::new(4, 1).unwrap();
        buffer.append_pcm2(&[1., 2.]);
        let mut output = [0.; 4];
        fill_output(&buffer.samples, &mut output, |sample| sample + 10.);
        assert_eq!(output, [11., 12., 10., 10.]);
    }

    #[test]
    fn output_fill_returns_while_the_producer_holds_the_ring() {
        let buffer = full_buffer();
        let ring = Arc::clone(&buffer.samples);
        let producer = buffer.samples.lock().unwrap();
        let (finished, result) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut output = [9.; 8];
            fill_output(&ring, &mut output, |sample| sample);
            finished.send(output).unwrap();
        });
        let outcome = result.recv_timeout(Duration::from_secs(2));
        drop(producer);
        worker.join().unwrap();
        assert_eq!(
            outcome.unwrap(),
            [0.; 8],
            "fill must return before producer release"
        );
        assert_eq!(queued(&buffer), 8);
        let mut output = [9.; 8];
        fill_output(&buffer.samples, &mut output, |sample| sample);
        assert_eq!(output, [0., 1., 2., 3., 4., 5., 6., 7.]);
    }

    #[test]
    fn output_fill_refuses_a_poisoned_ring() {
        let buffer = full_buffer();
        let poisoned = std::panic::catch_unwind(|| {
            let _held = buffer.samples.lock().unwrap();
            panic!("test producer failure");
        });
        assert!(poisoned.is_err());
        let mut output = [9.; 8];
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fill_output(&buffer.samples, &mut output, |sample| sample);
        }));
        assert!(outcome.is_err());
        assert_eq!(output, [9.; 8]);
    }
}
