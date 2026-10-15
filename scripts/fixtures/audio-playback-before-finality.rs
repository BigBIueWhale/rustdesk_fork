// Exact AudioHandler block from c3114e43d823c53ea1e267b36d3d41076be9dac0:src/client.rs.
// Block SHA-256: 402f1f1ec861a8e9fac810e30072f70a6fbeffa0d2d0a3f62c2c4b366d7d4db5
use super::*;

/// Audio handler for the [`Client`].
#[derive(Default)]
pub struct AudioHandler {
    audio_decoder: Option<(AudioDecoder, Vec<f32>)>,
    audio_format: Option<(u32, u32)>,
    audio_decode_failed: bool,
    #[cfg(target_os = "linux")]
    simple: Option<psimple::Simple>,
    #[cfg(not(target_os = "linux"))]
    audio_buffer: AudioBuffer,
    sample_rate: (u32, u32),
    #[cfg(not(target_os = "linux"))]
    audio_stream: Option<Box<dyn StreamTrait>>,
    channels: u16,
    #[cfg(not(target_os = "linux"))]
    device_channel: u16,
    #[cfg(not(target_os = "linux"))]
    ready: Arc<AtomicBool>,
}


impl AudioHandler {
    #[cfg(target_os = "linux")]
    fn start_audio(&mut self, format0: AudioFormat) -> ResultType<()> {
        use psimple::Simple;
        use pulse::sample::{Format, Spec};
        use pulse::stream::Direction;

        let spec = Spec {
            format: Format::F32le,
            channels: format0.channels as _,
            rate: format0.sample_rate as _,
        };
        if !spec.is_valid() {
            bail!("Invalid audio format");
        }

        self.simple = Some(Simple::new(
            None,                   // Use the default server
            &crate::get_app_name(), // Our application’s name
            Direction::Playback,    // We want a playback stream
            None,                   // Use the default device
            "playback",             // Description of our stream
            &spec,                  // Our sample format
            None,                   // Use default channel map
            None,                   // Use default buffering attributes
        )?);
        self.sample_rate = (format0.sample_rate, format0.sample_rate);
        Ok(())
    }

    /// Start the audio playback.
    #[cfg(not(target_os = "linux"))]
    fn start_audio(&mut self, format0: AudioFormat) -> ResultType<()> {
        let device = AUDIO_HOST
            .default_output_device()
            .ok_or_else(|| anyhow!("Failed to get default output device"))?;
        log::info!(
            "Using default output device: \"{}\"",
            device.name().unwrap_or("".to_owned())
        );
        let config = device.default_output_config().map_err(|e| anyhow!(e))?;
        let sample_format = config.sample_format();
        log::info!("Default output format: {:?}", config);
        log::info!("Remote input format: {:?}", format0);
        #[allow(unused_mut)]
        let mut config: StreamConfig = config.into();
        #[cfg(not(target_os = "ios"))]
        {
            // this makes ios audio output not work
            config.buffer_size = cpal::BufferSize::Fixed(64);
        }

        self.sample_rate = (format0.sample_rate, config.sample_rate.0);
        let mut build_output_stream = |config: StreamConfig| match sample_format {
            cpal::SampleFormat::I8 => self.build_output_stream::<i8>(&config, &device),
            cpal::SampleFormat::I16 => self.build_output_stream::<i16>(&config, &device),
            cpal::SampleFormat::I32 => self.build_output_stream::<i32>(&config, &device),
            cpal::SampleFormat::I64 => self.build_output_stream::<i64>(&config, &device),
            cpal::SampleFormat::U8 => self.build_output_stream::<u8>(&config, &device),
            cpal::SampleFormat::U16 => self.build_output_stream::<u16>(&config, &device),
            cpal::SampleFormat::U32 => self.build_output_stream::<u32>(&config, &device),
            cpal::SampleFormat::U64 => self.build_output_stream::<u64>(&config, &device),
            cpal::SampleFormat::F32 => self.build_output_stream::<f32>(&config, &device),
            cpal::SampleFormat::F64 => self.build_output_stream::<f64>(&config, &device),
            f => bail!("unsupported audio format: {:?}", f),
        };
        if config.channels > format0.channels as _ {
            let no_rechannel_config = StreamConfig {
                channels: format0.channels as _,
                ..config.clone()
            };
            if let Err(_) = build_output_stream(no_rechannel_config) {
                build_output_stream(config)?;
            }
        } else {
            build_output_stream(config)?;
        }

        Ok(())
    }

    /// Handle audio format and create an audio decoder.
    pub fn handle_format(&mut self, f: AudioFormat) {
        if self.audio_decode_failed {
            log::warn!(
                "dropping peer Opus format after native decoder failure; audio decode is failed closed"
            );
            return;
        }
        if !native_opus_format_within_limit(f.sample_rate, f.channels) {
            log::warn!(
                "dropping unsupported Opus format before native decode setup: sample_rate={}, channels={}",
                f.sample_rate,
                f.channels
            );
            return;
        }
        match native_opus_format_admission(self.audio_format, f.sample_rate, f.channels) {
            NativeOpusFormatAdmission::AcceptFirst => {}
            NativeOpusFormatAdmission::Duplicate => {
                log::debug!("dropping repeated peer Opus format without recreating native decoder");
                return;
            }
            NativeOpusFormatAdmission::Changed => {
                log::warn!(
                    "dropping peer Opus format change after decoder setup: sample_rate={}, channels={}",
                    f.sample_rate,
                    f.channels
                );
                return;
            }
        }
        self.audio_format = Some(native_opus_format_key(f.sample_rate, f.channels));
        match AudioDecoder::new(f.sample_rate, if f.channels > 1 { Stereo } else { Mono }) {
            Ok(d) => {
                let buffer = vec![0.; f.sample_rate as usize * f.channels as usize];
                self.audio_decoder = Some((d, buffer));
                self.channels = f.channels as _;
                allow_err!(self.start_audio(f));
            }
            Err(err) => {
                self.audio_decode_failed = true;
                log::error!("Failed to create audio decoder: {}", err);
            }
        }
    }

    /// Handle audio frame and play it.
    #[inline]
    pub fn handle_frame(&mut self, frame: AudioFrame) {
        if !native_opus_packet_within_limit(frame.data.len()) {
            log::warn!(
                "dropping oversized Opus packet before native decode: {} > {}",
                frame.data.len(),
                MAX_NATIVE_OPUS_PACKET_BYTES
            );
            return;
        }
        #[cfg(not(target_os = "linux"))]
        if self.audio_stream.is_none() || !self.ready.load(Ordering::Acquire) {
            return;
        }
        #[cfg(target_os = "linux")]
        if self.simple.is_none() {
            log::debug!("PulseAudio simple binding does not exists");
            return;
        }
        if self.audio_decode_failed {
            return;
        }
        if let Some((d, buffer)) = self.audio_decoder.as_mut() {
            match d.decode_float(&frame.data, buffer, false) {
                Ok(n) => {
                    let channels = self.channels;
                    let n = n * (channels as usize);
                    #[cfg(not(target_os = "linux"))]
                    {
                        let sample_rate0 = self.sample_rate.0;
                        let sample_rate = self.sample_rate.1;
                        let mut buffer = buffer[0..n].to_owned();
                        if sample_rate != sample_rate0 {
                            buffer = crate::audio_resample(
                                &buffer[0..n],
                                sample_rate0,
                                sample_rate,
                                channels,
                            );
                        }
                        if self.channels != self.device_channel {
                            buffer = crate::audio_rechannel(
                                buffer,
                                sample_rate,
                                sample_rate,
                                self.channels,
                                self.device_channel,
                            );
                        }
                        self.audio_buffer.append_pcm(&buffer);
                    }
                    #[cfg(target_os = "linux")]
                    {
                        let data_u8 = unsafe {
                            std::slice::from_raw_parts::<u8>(buffer.as_ptr() as _, n * 4)
                        };
                        self.simple.as_mut().map(|x| x.write(data_u8));
                    }
                }
                Err(err) => {
                    log::warn!(
                        "native Opus decode failed; refusing further audio decoder recreation: {err}"
                    );
                    self.audio_decoder = None;
                    self.audio_decode_failed = true;
                }
            }
        }
    }

    /// Build audio output stream for current device.
    #[cfg(not(target_os = "linux"))]
    fn build_output_stream<T: cpal::Sample + cpal::SizedSample + cpal::FromSample<f32>>(
        &mut self,
        config: &StreamConfig,
        device: &Device,
    ) -> ResultType<()> {
        self.device_channel = config.channels;
        let err_fn = move |err| {
            // too many errors, will improve later
            log::trace!("an error occurred on stream: {}", err);
        };
        self.audio_buffer
            .resize(config.sample_rate.0 as _, config.channels as _);
        let audio_buffer = self.audio_buffer.samples.clone();
        let ready = self.ready.clone();
        let timeout = None;
        let stream = device.build_output_stream(
            config,
            move |data: &mut [T], _info: &cpal::OutputCallbackInfo| {
                ready.store(true, Ordering::Release);
                audio_buffer::fill_output(&audio_buffer, data, T::from_sample);
            },
            err_fn,
            timeout,
        )?;
        stream.play()?;
        self.audio_stream = Some(Box::new(stream));
        Ok(())
    }
}

#[path = "../../src/client/audio_playback_tests.rs"]
mod audio_playback_tests;

