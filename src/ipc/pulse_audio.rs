use super::*;
use std::{
    cell::RefCell,
    collections::VecDeque,
    rc::Rc,
    time::{Duration, Instant},
};

const PA_POLL_INTERVAL: Duration = Duration::from_millis(10);
const PA_AUTHORITY_INTERVAL: Duration = Duration::from_millis(100);
const PA_SETUP_TIMEOUT: Duration = Duration::from_secs(2);
const PA_QUEUED_FRAMES: usize = 8;
const PA_MAX_FRAGMENT_BYTES: usize = PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES * 32;

#[derive(Default)]
struct PaSourceLookup {
    selected: Option<PaSource>,
    ambiguous: bool,
    done: bool,
    failed: bool,
}

struct PaSource {
    name: String,
    index: u32,
}

#[derive(Default)]
struct PaDefaultOutput {
    name: Option<String>,
    subscribed: Option<bool>,
    done: bool,
    changed: bool,
}

#[derive(Default)]
struct PaCaptureFrames {
    partial: Vec<u8>,
    ready: VecDeque<Bytes>,
}

impl PaCaptureFrames {
    fn append(&mut self, data: &[u8]) -> ResultType<()> {
        if data.len() > PA_MAX_FRAGMENT_BYTES {
            bail!("PulseAudio capture fragment exceeds the bounded record buffer");
        }
        let mut remaining = data;
        while !remaining.is_empty() {
            let take = remaining
                .len()
                .min(PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES - self.partial.len());
            self.partial.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            if self.partial.len() == PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES {
                if self.ready.len() == PA_QUEUED_FRAMES {
                    self.ready.pop_front();
                }
                self.ready.push_back(Bytes::from(std::mem::take(&mut self.partial)));
            }
        }
        Ok(())
    }

    fn append_hole(&mut self, mut bytes: usize) -> ResultType<()> {
        if bytes > PA_MAX_FRAGMENT_BYTES {
            bail!("PulseAudio capture hole exceeds the bounded record buffer");
        }
        let zeros = [0; PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES];
        while bytes != 0 {
            let take = bytes.min(zeros.len());
            self.append(&zeros[..take])?;
            bytes -= take;
        }
        Ok(())
    }

    fn next_frame(&mut self) -> Option<Bytes> {
        self.ready.pop_front().map(|frame| {
            if frame.iter().all(|byte| *byte == 0) {
                Bytes::new()
            } else {
                frame
            }
        })
    }
}

fn iterate_pa(mainloop: &mut pulse::mainloop::standard::Mainloop) -> ResultType<()> {
    match mainloop.iterate(false) {
        pulse::mainloop::standard::IterateResult::Success(_) => Ok(()),
        pulse::mainloop::standard::IterateResult::Quit(_) => bail!("PulseAudio main loop quit"),
        pulse::mainloop::standard::IterateResult::Err(err) => {
            bail!("PulseAudio main loop failed: {err}")
        }
    }
}

async fn wait_for_pa<T>(
    stream: &mut ConnectionTmpl<T>,
    peer: &LinuxProcessIdentity,
    token: &str,
    last_authority_check: &mut Instant,
) -> ResultType<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::time::timeout(PA_POLL_INTERVAL, stream.inner.next()).await {
        Err(_) => {}
        Ok(None) => bail!("PulseAudio capture owner closed the IPC stream"),
        Ok(Some(Ok(_))) => bail!("unexpected _pa client frame after StartCapture"),
        Ok(Some(Err(err))) => return Err(err.into()),
    }
    if last_authority_check.elapsed() >= PA_AUTHORITY_INTERVAL {
        validate_pulse_audio_start_authority(peer, token).await?;
        *last_authority_check = Instant::now();
    }
    Ok(())
}

async fn capture<T>(
    stream: &mut ConnectionTmpl<T>,
    peer: &LinuxProcessIdentity,
    token: &str,
    requested_source: &str,
) -> ResultType<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut mainloop = pulse::mainloop::standard::Mainloop::new()
        .ok_or_else(|| anyhow::anyhow!("could not create PulseAudio main loop"))?;
    let mut context = pulse::context::Context::new(&mainloop, &crate::get_app_name())
        .ok_or_else(|| anyhow::anyhow!("could not create PulseAudio context"))?;
    context.connect(None, pulse::context::FlagSet::NOAUTOSPAWN, None)?;
    let mut last_authority_check = Instant::now();
    let deadline = Instant::now() + PA_SETUP_TIMEOUT;
    loop {
        iterate_pa(&mut mainloop)?;
        match context.get_state() {
            pulse::context::State::Ready => break,
            pulse::context::State::Failed | pulse::context::State::Terminated => {
                bail!("PulseAudio context did not become ready")
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            bail!("PulseAudio context connection timed out");
        }
        wait_for_pa(stream, peer, token, &mut last_authority_check).await?;
    }

    let default_output = Rc::new(RefCell::new(PaDefaultOutput::default()));
    if requested_source.is_empty() {
        let observed = Rc::clone(&default_output);
        context.set_subscribe_callback(Some(Box::new(move |facility, _, _| {
            if facility == Some(pulse::context::subscribe::Facility::Server) {
                observed.borrow_mut().changed = true;
            }
        })));
        let subscribed = Rc::clone(&default_output);
        let subscription = context.subscribe(
            pulse::context::subscribe::InterestMaskSet::SERVER,
            move |success| subscribed.borrow_mut().subscribed = Some(success),
        );
        let observed = Rc::clone(&default_output);
        let introspector = context.introspect();
        let operation = introspector.get_server_info(move |info| {
            let mut output = observed.borrow_mut();
            output.name = info
                .default_sink_name
                .as_deref()
                .filter(|name| !name.is_empty() && name.len() <= 1024)
                .map(str::to_owned);
            output.done = true;
        });
        let deadline = Instant::now() + PA_SETUP_TIMEOUT;
        loop {
            iterate_pa(&mut mainloop)?;
            if context.get_state() != pulse::context::State::Ready {
                bail!("PulseAudio context disconnected during default-output lookup");
            }
            {
                let output = default_output.borrow();
                if output.subscribed == Some(false) {
                    bail!("PulseAudio default-output observation failed");
                }
                if output.changed {
                    bail!("PulseAudio default output changed during source lookup");
                }
                if output.done && output.subscribed == Some(true) {
                    break;
                }
            }
            if Instant::now() >= deadline {
                bail!("PulseAudio default-output lookup timed out");
            }
            wait_for_pa(stream, peer, token, &mut last_authority_check).await?;
        }
        drop(operation);
        drop(subscription);
    }
    let default_sink = default_output.borrow().name.clone();
    if requested_source.is_empty() && default_sink.is_none() {
        bail!("PulseAudio default output is unavailable");
    }
    let lookup = Rc::new(RefCell::new(PaSourceLookup::default()));
    let callback_lookup = Rc::clone(&lookup);
    let requested = requested_source.to_owned();
    let introspector = context.introspect();
    let operation = introspector.get_source_info_list(move |item| {
        let mut lookup = callback_lookup.borrow_mut();
        match item {
            pulse::callbacks::ListResult::Item(info) => {
                if let Some(name) = info.name.as_ref() {
                    if name.is_empty() || name.len() > 1024 {
                        return;
                    }
                    let matches = if requested.is_empty() {
                        info.monitor_of_sink.is_some()
                            && info.monitor_of_sink_name.as_deref() == default_sink.as_deref()
                    } else {
                        name.as_ref() == requested.as_str()
                    };
                    if matches {
                        if lookup.selected.is_some() {
                            lookup.ambiguous = true;
                        } else {
                            lookup.selected = Some(PaSource {
                                name: name.to_string(),
                                index: info.index,
                            });
                        }
                    }
                }
            }
            pulse::callbacks::ListResult::End => lookup.done = true,
            pulse::callbacks::ListResult::Error => lookup.failed = true,
        }
    });
    let deadline = Instant::now() + PA_SETUP_TIMEOUT;
    loop {
        iterate_pa(&mut mainloop)?;
        if context.get_state() != pulse::context::State::Ready {
            bail!("PulseAudio context disconnected during source lookup");
        }
        if lookup.borrow().failed {
            bail!("PulseAudio source lookup failed");
        }
        if lookup.borrow().done {
            break;
        }
        if Instant::now() >= deadline {
            bail!("PulseAudio source lookup timed out");
        }
        wait_for_pa(stream, peer, token, &mut last_authority_check).await?;
    }
    drop(operation);
    drop(introspector);
    let source = {
        let mut lookup = lookup.borrow_mut();
        if lookup.ambiguous {
            bail!("PulseAudio source selection is ambiguous");
        }
        lookup.selected.take()
    }
    .ok_or_else(|| anyhow::anyhow!("selected PulseAudio source is unavailable"))?;
    if default_output.borrow().changed {
        bail!("PulseAudio default output changed during source lookup");
    }

    let spec = pulse::sample::Spec {
        format: pulse::sample::Format::F32le,
        channels: 2,
        rate: crate::platform::PA_SAMPLE_RATE,
    };
    let mut recorder = pulse::stream::Stream::new(&mut context, "record", &spec, None)
        .ok_or_else(|| anyhow::anyhow!("could not create PulseAudio record stream"))?;
    let attr = pulse::def::BufferAttr {
        maxlength: (PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES * PA_QUEUED_FRAMES) as u32,
        tlength: u32::MAX,
        prebuf: u32::MAX,
        minreq: u32::MAX,
        fragsize: PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES as u32,
    };
    recorder.connect_record(
        Some(&source.name),
        Some(&attr),
        pulse::stream::FlagSet::DONT_MOVE,
    )?;
    let deadline = Instant::now() + PA_SETUP_TIMEOUT;
    loop {
        iterate_pa(&mut mainloop)?;
        if context.get_state() != pulse::context::State::Ready || default_output.borrow().changed {
            bail!("PulseAudio output changed during recording setup");
        }
        match recorder.get_state() {
            pulse::stream::State::Ready => {
                if recorder.get_device_index() != Some(source.index) {
                    bail!("PulseAudio recording source changed during connection");
                }
                break;
            }
            pulse::stream::State::Failed | pulse::stream::State::Terminated => {
                bail!("PulseAudio record stream did not become ready")
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            bail!("PulseAudio record stream connection timed out");
        }
        wait_for_pa(stream, peer, token, &mut last_authority_check).await?;
    }
    log::info!("pa source: {:?}", source.name);

    let mut frames = PaCaptureFrames::default();
    loop {
        iterate_pa(&mut mainloop)?;
        if default_output.borrow().changed {
            bail!("PulseAudio default output changed");
        }
        if context.get_state() != pulse::context::State::Ready
            || recorder.get_state() != pulse::stream::State::Ready
            || recorder.get_device_index() != Some(source.index)
        {
            bail!("PulseAudio capture stream disconnected");
        }
        loop {
            match recorder.peek()? {
                pulse::stream::PeekResult::Empty => break,
                pulse::stream::PeekResult::Hole(bytes) => frames.append_hole(bytes)?,
                pulse::stream::PeekResult::Data(data) => frames.append(data)?,
            }
            recorder.discard()?;
        }
        if let Some(frame) = frames.next_frame() {
            stream
                .send_pulse_audio_frame_timeout(frame, PULSE_AUDIO_IPC_IO_TIMEOUT_MS)
                .await?;
        }
        wait_for_pa(stream, peer, token, &mut last_authority_check).await?;
    }
}

async fn handle_pa_stream(stream: Conn) {
    let mut stream = Connection::new_pulse_audio(stream);
    if let Err(err) = validate_pulse_audio_requester(&stream) {
        log::warn!("Rejected _pa client without capture requester authority: {err}");
        return;
    }
    let request = match stream
        .next_pulse_audio_request_timeout(PULSE_AUDIO_IPC_IO_TIMEOUT_MS)
        .await
    {
        Ok(Some(request)) => request,
        Ok(None) => {
            log::warn!("Rejected _pa client with malformed capture request");
            return;
        }
        Err(err) => {
            log::warn!("Rejected _pa client without timely capture authority: {err}");
            return;
        }
    };
    let LinuxPulseAudioIpcRequest::StartCapture { token, source } = request;
    let peer = match validate_pulse_audio_capture_request(&stream, &token).await {
        Ok(peer) => peer,
        Err(err) => {
            log::warn!("Rejected _pa client with invalid audio capture authority: {err}");
            return;
        }
    };
    if let Err(err) = capture(&mut stream, &peer, &token, &source).await {
        log::info!("PulseAudio capture ended: {err}");
    }
}

#[tokio::main(flavor = "current_thread")]
pub async fn start_pa() {
    match new_listener("_pa").await {
        Ok(mut incoming) => {
            while let Some(result) = incoming.next().await {
                match result {
                    Ok(stream) => handle_pa_stream(stream).await,
                    Err(err) => log::error!("Couldn't get pa client: {err:?}"),
                }
            }
        }
        Err(err) => log::error!("Failed to start pa ipc server: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type NativeCapture<'a> =
        std::pin::Pin<Box<dyn std::future::Future<Output = ResultType<()>> + 'a>>;

    async fn native_pactl_output(args: &[&str]) -> std::process::Output {
        assert_eq!(std::env::var("RUSTDESK_PA_NATIVE_TEST").unwrap(), "1");
        let mut command = tokio::process::Command::new(
            std::env::var("RUSTDESK_PA_NATIVE_PACTL").unwrap(),
        );
        command.args(args).kill_on_drop(true);
        tokio::time::timeout(Duration::from_secs(2), command.output())
            .await.unwrap().unwrap()
    }

    async fn native_pactl(args: &[&str]) -> String {
        let output = native_pactl_output(args).await;
        assert!(output.status.success(), "pactl {args:?}: {}",
            String::from_utf8_lossy(&output.stderr));
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    async fn native_source(name: &str, description: &str) -> (u32, u32, String) {
        let module = native_pactl(&[
            "load-module", "module-null-sink", &format!("sink_name={name}"),
            &format!("sink_properties=device.description={description}"),
        ]).await.parse::<u32>().unwrap();
        let sources: serde_json::Value =
            serde_json::from_str(&native_pactl(&["--format=json", "list", "sources"]).await)
                .unwrap();
        let monitor = format!("{name}.monitor");
        let matches: Vec<_> = sources.as_array().unwrap().iter()
            .filter(|source| source["name"].as_str() == Some(monitor.as_str())).collect();
        assert_eq!(matches.len(), 1);
        (module, matches[0]["index"].as_u64().unwrap() as u32,
            matches[0]["description"].as_str().unwrap().to_owned())
    }

    async fn native_recording() -> (u32, u32) {
        let text = native_pactl(&["list", "short", "source-outputs"]).await;
        let rows: Vec<_> = text.lines().collect();
        assert_eq!(rows.len(), 1);
        let fields: Vec<_> = rows[0].split_whitespace().collect();
        (fields[0].parse().unwrap(), fields[1].parse().unwrap())
    }

    async fn native_frame(
        capture: &mut NativeCapture<'_>,
        client: &mut ConnectionTmpl<tokio::net::UnixStream>,
    ) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    result = &mut *capture => panic!("capture ended before a frame: {result:?}"),
                    frame = client.next_pulse_audio_frame_timeout(100) => {
                        if frame.unwrap().is_some() { break; }
                    }
                }
            }
        }).await.unwrap();
    }

    async fn native_capture_ends(
        capture: &mut NativeCapture<'_>,
        client: &mut ConnectionTmpl<tokio::net::UnixStream>,
    ) -> bool {
        tokio::time::timeout(Duration::from_millis(750), async {
            loop {
                tokio::select! {
                    result = &mut *capture => break result.is_err(),
                    frame = client.next_pulse_audio_frame_timeout(100) => { frame.unwrap(); }
                }
            }
        }).await.unwrap_or(false)
    }

    async fn native_request_refused(
        peer: &LinuxProcessIdentity, token: &str, source: &str,
    ) -> bool {
        let (helper_socket, client_socket) = tokio::net::UnixStream::pair().unwrap();
        let mut helper = ConnectionTmpl::new_pulse_audio(helper_socket);
        let mut client = ConnectionTmpl::new_pulse_audio(client_socket);
        let mut capture: NativeCapture<'_> =
            Box::pin(super::capture(&mut helper, peer, token, source));
        let refused = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    result = &mut capture => break result.is_err(),
                    frame = client.next_pulse_audio_frame_timeout(100) => {
                        if frame.unwrap().is_some() { break false; }
                    }
                }
            }
        }).await.unwrap();
        drop(capture);
        drop(helper);
        drop(client);
        assert_native_record_streams(0).await;
        refused
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires the private native PulseAudio source fixture"]
    async fn real_source_names_select_devices_with_duplicate_descriptions() {
        async fn selected_source(peer: &LinuxProcessIdentity, token: &str, name: &str) -> Option<u32> {
            let (helper_socket, client_socket) = tokio::net::UnixStream::pair().unwrap();
            let mut helper = ConnectionTmpl::new_pulse_audio(helper_socket);
            let mut client = ConnectionTmpl::new_pulse_audio(client_socket);
            let mut capture: NativeCapture<'_> =
                Box::pin(super::capture(&mut helper, peer, token, name));
            let started = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    tokio::select! {
                        _ = &mut capture => break false,
                        frame = client.next_pulse_audio_frame_timeout(100) => {
                            if frame.unwrap().is_some() { break true; }
                        }
                    }
                }
            }).await.unwrap();
            let source = if started { Some(native_recording().await.1) } else { None };
            drop(capture);
            drop(helper);
            drop(client);
            assert_native_record_streams(0).await;
            source
        }

        assert_native_record_streams(0).await;
        let original_default = native_pactl(&["get-default-source"]).await;
        let first = native_source("rd_named_first", "rd_shared_description").await;
        let second = native_source("rd_named_second", "rd_shared_description").await;
        assert_eq!(first.2, second.2);
        let sources = tokio::task::spawn_blocking(crate::platform::linux::get_pa_sources)
            .await.unwrap();
        native_pactl(&["set-default-source", "rd_named_second.monitor"]).await;
        let default = tokio::task::spawn_blocking(crate::common::get_default_sound_input)
            .await.unwrap();
        let authority = crate::audio_service::PaCaptureNativeFixture::new().unwrap();
        let peer = current_linux_process_identity().unwrap();
        let selected_first = selected_source(&peer, authority.token(), "rd_named_first.monitor").await;
        let selected_second = selected_source(&peer, authority.token(), "rd_named_second.monitor").await;
        let description_refused = native_request_refused(&peer, authority.token(), &first.2).await;
        native_pactl(&["set-default-source", &original_default]).await;
        native_pactl(&["unload-module", &second.0.to_string()]).await;
        native_pactl(&["unload-module", &first.0.to_string()]).await;
        println!("PA_SOURCE_NAMES first={selected_first:?} expected_first={} second={selected_second:?} expected_second={} default={default:?} description_refused={description_refused}", first.1, second.1);
        assert!(sources.contains(&("rd_named_first.monitor".to_owned(), first.2.clone())));
        assert!(sources.contains(&("rd_named_second.monitor".to_owned(), second.2.clone())));
        assert_eq!(selected_first, Some(first.1));
        assert_eq!(selected_second, Some(second.1));
        assert_eq!(default.as_deref(), Some("rd_named_second.monitor"));
        assert!(description_refused);
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires the private native PulseAudio source fixture"]
    async fn real_source_selection_tracks_default_output() {
        assert_native_record_streams(0).await;
        let original_default = native_pactl(&["get-default-sink"]).await;
        let first = native_source("rd_default_first", "rd_default_first").await;
        let second = native_source("rd_default_second", "rd_default_second").await;
        native_pactl(&["set-default-sink", "rd_default_second"]).await;
        let authority = crate::audio_service::PaCaptureNativeFixture::new().unwrap();
        let peer = current_linux_process_identity().unwrap();
        let (helper_socket, client_socket) = tokio::net::UnixStream::pair().unwrap();
        let mut helper = ConnectionTmpl::new_pulse_audio(helper_socket);
        let mut client = ConnectionTmpl::new_pulse_audio(client_socket);
        let mut capture: NativeCapture<'_> =
            Box::pin(super::capture(&mut helper, &peer, authority.token(), ""));
        native_frame(&mut capture, &mut client).await;
        let selected = native_recording().await.1;
        native_pactl(&["set-default-sink", "rd_default_first"]).await;
        let retired = native_capture_ends(&mut capture, &mut client).await;
        drop(capture);
        drop(helper);
        drop(client);
        assert_native_record_streams(0).await;
        let (helper_socket, client_socket) = tokio::net::UnixStream::pair().unwrap();
        let mut helper = ConnectionTmpl::new_pulse_audio(helper_socket);
        let mut client = ConnectionTmpl::new_pulse_audio(client_socket);
        let mut capture: NativeCapture<'_> =
            Box::pin(super::capture(&mut helper, &peer, authority.token(), ""));
        native_frame(&mut capture, &mut client).await;
        let replacement = native_recording().await.1;
        drop(capture);
        drop(helper);
        drop(client);
        assert_native_record_streams(0).await;
        native_pactl(&["set-default-sink", &original_default]).await;
        native_pactl(&["unload-module", &second.0.to_string()]).await;
        native_pactl(&["unload-module", &first.0.to_string()]).await;
        println!("PA_SOURCE_DEFAULT selected={selected} expected={} retired={retired} replacement={replacement} replacement_expected={}", second.1, first.1);
        assert_eq!(selected, second.1, "capture must use the current default output");
        assert!(retired, "default-output change must retire the old capture");
        assert_eq!(replacement, first.1, "fresh capture must resolve the new default");
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires the private native PulseAudio source fixture"]
    async fn real_source_selection_rejects_unavailable_or_ambiguous_requests() {
        assert_native_record_streams(0).await;
        let first = native_source("rd_explicit_first", "rd_explicit_description").await;
        let authority = crate::audio_service::PaCaptureNativeFixture::new().unwrap();
        let peer = current_linux_process_identity().unwrap();
        let (helper_socket, client_socket) = tokio::net::UnixStream::pair().unwrap();
        let mut helper = ConnectionTmpl::new_pulse_audio(helper_socket);
        let mut client = ConnectionTmpl::new_pulse_audio(client_socket);
        let mut capture: NativeCapture<'_> =
            Box::pin(super::capture(&mut helper, &peer, authority.token(), "rd_explicit_first.monitor"));
        native_frame(&mut capture, &mut client).await;
        let selected = native_recording().await.1;
        drop(capture);
        drop(helper);
        drop(client);
        assert_native_record_streams(0).await;
        let missing = native_request_refused(&peer, authority.token(), "rd_absent_source_description").await;
        let second = native_source("rd_explicit_second", "rd_explicit_description").await;
        assert_eq!(first.2, second.2, "fixture must publish duplicate descriptions");
        let ambiguous = native_request_refused(&peer, authority.token(), &first.2).await;
        native_pactl(&["unload-module", &second.0.to_string()]).await;
        let recovered = !native_request_refused(&peer, authority.token(), "rd_explicit_first.monitor").await;
        native_pactl(&["unload-module", &first.0.to_string()]).await;
        println!("PA_SOURCE_EXPLICIT selected={selected} expected={} missing_refused={missing} ambiguous_refused={ambiguous} recovered={recovered}", first.1);
        assert_eq!(selected, first.1);
        assert!(missing, "missing explicit device must not capture a fallback monitor");
        assert!(ambiguous, "duplicate descriptions must not select an arbitrary device");
        assert!(recovered, "unique explicit device must recover without daemon restart");
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires the private native PulseAudio source fixture"]
    async fn real_source_selection_retires_on_device_removal_and_refuses_move() {
        assert_native_record_streams(0).await;
        let source = native_source("rd_owned_source", "rd_owned_description").await;
        let authority = crate::audio_service::PaCaptureNativeFixture::new().unwrap();
        let peer = current_linux_process_identity().unwrap();
        let (helper_socket, client_socket) = tokio::net::UnixStream::pair().unwrap();
        let mut helper = ConnectionTmpl::new_pulse_audio(helper_socket);
        let mut client = ConnectionTmpl::new_pulse_audio(client_socket);
        let mut capture: NativeCapture<'_> =
            Box::pin(super::capture(&mut helper, &peer, authority.token(), "rd_owned_source.monitor"));
        native_frame(&mut capture, &mut client).await;
        let recording = native_recording().await;
        let moved = native_pactl_output(&[
            "move-source-output", &recording.0.to_string(), "rd_pa_test.monitor",
        ]).await.status.success();
        let after_move = native_recording().await.1;
        native_pactl(&["unload-module", &source.0.to_string()]).await;
        let retired = native_capture_ends(&mut capture, &mut client).await;
        drop(capture);
        drop(helper);
        drop(client);
        assert_native_record_streams(0).await;
        println!("PA_SOURCE_LIFETIME initial={} expected={} move_accepted={moved} after_move={after_move} removal_retired={retired}", recording.1, source.1);
        assert_eq!(recording.1, source.1);
        assert!(!moved, "recording must reject a move to an unselected device");
        assert_eq!(after_move, source.1);
        assert!(retired, "device removal must terminate the capture");
    }


    async fn assert_native_record_streams(expected: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(750);
        loop {
            let mut command = tokio::process::Command::new(
                std::env::var("RUSTDESK_PA_NATIVE_PACTL").unwrap(),
            );
            command
                .args(["list", "short", "source-outputs"])
                .kill_on_drop(true);
            let output = tokio::time::timeout(Duration::from_millis(500), command.output())
                .await
                .unwrap()
                .unwrap();
            assert!(
                output.status.success(),
                "native recording-stream census failed"
            );
            let streams = std::str::from_utf8(&output.stdout).unwrap().lines().count();
            if streams == expected {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "native recording streams: expected={expected} actual={streams}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[test]
    fn record_fragments_preserve_frame_shape_and_bound_stale_audio() {
        let mut frames = PaCaptureFrames::default();
        frames.append(&vec![1; PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES / 2]).unwrap();
        assert!(frames.next_frame().is_none());
        frames.append(&vec![2; PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES / 2]).unwrap();
        let frame = frames.next_frame().unwrap();
        assert_eq!(frame.len(), PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES);
        assert!(frame[..frame.len() / 2].iter().all(|byte| *byte == 1));
        assert!(frame[frame.len() / 2..].iter().all(|byte| *byte == 2));

        frames.append_hole(PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES).unwrap();
        assert!(frames.next_frame().unwrap().is_empty());
        for value in 1..=PA_QUEUED_FRAMES + 2 {
            frames.append(&vec![value as u8; PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES]).unwrap();
        }
        assert_eq!(frames.ready.len(), PA_QUEUED_FRAMES);
        assert_eq!(frames.next_frame().unwrap()[0], 3);
        assert!(frames.append(&vec![0; PA_MAX_FRAGMENT_BYTES + 1]).is_err());
        assert!(frames.append_hole(PA_MAX_FRAGMENT_BYTES + 1).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn accepted_owner_close_interrupts_silent_capture_wait() {
        let (socket, owner) = tokio::net::UnixStream::pair().unwrap();
        let mut stream = ConnectionTmpl::new_pulse_audio(socket);
        let peer = current_linux_process_identity().unwrap();
        let mut last_authority_check = Instant::now();
        drop(owner);
        assert!(tokio::time::timeout(
            Duration::from_millis(100),
            wait_for_pa(&mut stream, &peer, "unused", &mut last_authority_check)
        )
        .await
        .unwrap()
        .is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires the private PulseAudio daemon and monitor fixture"]
    async fn real_monitor_capture_revokes_after_audio_stops() {
        assert_eq!(std::env::var("RUSTDESK_PA_NATIVE_TEST").unwrap(), "1");
        assert_native_record_streams(0).await;
        let authority = crate::audio_service::PaCaptureNativeFixture::new().unwrap();
        let peer = current_linux_process_identity().unwrap();
        let (helper_socket, client_socket) = tokio::net::UnixStream::pair().unwrap();
        let mut helper = ConnectionTmpl::new_pulse_audio(helper_socket);
        let mut client = ConnectionTmpl::new_pulse_audio(client_socket);
        let mut capture = Box::pin(capture(&mut helper, &peer, authority.token(), ""));

        let signal_deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        let mut frames_seen = 0;
        let mut empty_frames = 0;
        loop {
            let frame = tokio::select! {
                result = &mut capture => panic!("capture ended before source audio: {result:?}"),
                frame = client.next_pulse_audio_frame_timeout(500) => frame.unwrap(),
                _ = tokio::time::sleep_until(signal_deadline) => panic!(
                    "real monitor produced no audio: frames={frames_seen} empty={empty_frames}"
                ),
            };
            if let Some(frame) = frame.as_ref() {
                frames_seen += 1;
                if frame.is_empty() {
                    empty_frames += 1;
                }
            }
            if frame
                .as_ref()
                .is_some_and(|frame| frame.iter().any(|sample| *sample != 0))
            {
                break;
            }
        }

        assert_native_record_streams(1).await;
        let pactl = std::env::var("RUSTDESK_PA_NATIVE_PACTL").unwrap();
        let module = std::env::var("RUSTDESK_PA_NATIVE_SINE_MODULE").unwrap();
        let unload = tokio::task::spawn_blocking(move || {
            std::process::Command::new(pactl)
                .args(["unload-module", &module])
                .status()
        })
        .await
        .unwrap()
        .unwrap();
        assert!(unload.success());

        let quiet_until = tokio::time::Instant::now() + Duration::from_millis(200);
        loop {
            tokio::select! {
                result = &mut capture => panic!("capture ended before authority revocation: {result:?}"),
                frame = client.next_pulse_audio_frame_timeout(100) => { frame.unwrap(); }
                _ = tokio::time::sleep_until(quiet_until) => break,
            }
        }
        authority.revoke();
        let result = tokio::time::timeout(Duration::from_millis(600), async {
            loop {
                tokio::select! {
                    result = &mut capture => break result,
                    frame = client.next_pulse_audio_frame_timeout(100) => { frame.unwrap(); }
                }
            }
        })
        .await
        .unwrap();
        let err = result.unwrap_err();
        assert!(err.to_string().contains("authority"), "{err}");
        drop(capture);
        drop(helper);
        drop(client);
        assert_native_record_streams(0).await;

        let old_token = authority.token().to_owned();
        let replacement = crate::audio_service::PaCaptureNativeFixture::new().unwrap();
        assert_ne!(old_token, replacement.token());
        assert!(validate_pulse_audio_start_authority(&peer, &old_token)
            .await
            .is_err());
        validate_pulse_audio_start_authority(&peer, replacement.token())
            .await
            .unwrap();

        let pactl = std::env::var("RUSTDESK_PA_NATIVE_PACTL").unwrap();
        let load = tokio::task::spawn_blocking(move || {
            std::process::Command::new(pactl)
                .args(["load-module", "module-sine", "sink=rd_pa_test", "frequency=440"])
                .output()
        })
        .await
        .unwrap()
        .unwrap();
        assert!(load.status.success());
        let replacement_module = std::str::from_utf8(&load.stdout)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        assert!(replacement_module > 0);

        let (helper_socket, client_socket) = tokio::net::UnixStream::pair().unwrap();
        let mut helper = ConnectionTmpl::new_pulse_audio(helper_socket);
        let mut client = ConnectionTmpl::new_pulse_audio(client_socket);
        let mut capture = Box::pin(super::capture(&mut helper, &peer, replacement.token(), ""));
        let signal_deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            let frame = tokio::select! {
                result = &mut capture => panic!("replacement capture ended before source audio: {result:?}"),
                frame = client.next_pulse_audio_frame_timeout(500) => frame.unwrap(),
                _ = tokio::time::sleep_until(signal_deadline) => panic!("replacement capture produced no source audio"),
            };
            if frame.is_some_and(|frame| frame.iter().any(|sample| *sample != 0)) {
                break;
            }
        }
        assert_native_record_streams(1).await;
        drop(authority);
        validate_pulse_audio_start_authority(&peer, replacement.token())
            .await
            .unwrap();

        let until = tokio::time::Instant::now() + Duration::from_millis(500);
        let mut nonzero_frames = 0;
        loop {
            tokio::select! {
                result = &mut capture => panic!("fresh capture ended after old-owner retirement: {result:?}"),
                frame = client.next_pulse_audio_frame_timeout(100) => {
                    if frame.unwrap().is_some_and(|frame| frame.iter().any(|sample| *sample != 0)) {
                        nonzero_frames += 1;
                    }
                }
                _ = tokio::time::sleep_until(until) => break,
            }
        }
        assert!(nonzero_frames > 0, "replacement capture produced no source audio");
        assert_native_record_streams(1).await;
        replacement.revoke();
        let result = tokio::time::timeout(Duration::from_millis(600), async {
            loop {
                tokio::select! {
                    result = &mut capture => break result,
                    frame = client.next_pulse_audio_frame_timeout(100) => { frame.unwrap(); }
                }
            }
        })
        .await
        .unwrap();
        let err = result.unwrap_err();
        assert!(err.to_string().contains("authority"), "{err}");
        assert!(validate_pulse_audio_start_authority(&peer, replacement.token())
            .await
            .is_err());
        drop(capture);
        drop(helper);
        drop(client);
        assert_native_record_streams(0).await;

        let pactl = std::env::var("RUSTDESK_PA_NATIVE_PACTL").unwrap();
        let unload = tokio::task::spawn_blocking(move || {
            std::process::Command::new(pactl)
                .args(["unload-module", &replacement_module.to_string()])
                .status()
        })
        .await
        .unwrap()
        .unwrap();
        assert!(unload.success());
        println!("PA_CAPTURE_RETIREMENT=pass source_outputs=0,1,0,1,1,0 old_token=refused old_guard=retired successor_nonzero_frames={nonzero_frames} successor=revoked");
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires a private native Unix _pa endpoint and a separate same-UID client"]
    async fn real_kernel_pa_admission_refuses_same_uid_child_with_token() {
        assert_eq!(std::env::var("RUSTDESK_PA_NATIVE_TEST").unwrap(), "1");
        if std::env::var("RUSTDESK_PA_NATIVE_SILENT_ATTACKER").as_deref() == Ok("1") {
            let path = std::env::var("RUSTDESK_PA_NATIVE_ATTACKER_SOCKET").unwrap();
            let mut stream = connect_with_path(1_000, &path, "_pa").await.unwrap();
            assert!(tokio::time::timeout(
                Duration::from_millis(750),
                stream.next_pulse_audio_frame_timeout(1_000)
            )
            .await
            .unwrap()
            .is_err());
            return;
        }
        if std::env::var("RUSTDESK_PA_NATIVE_ATTACKER").as_deref() == Ok("1") {
            let path = std::env::var("RUSTDESK_PA_NATIVE_ATTACKER_SOCKET").unwrap();
            let token = std::env::var("RUSTDESK_PA_NATIVE_ATTACKER_TOKEN").unwrap();
            let mut stream = connect_with_path(1_000, &path, "_pa").await.unwrap();
            stream
                .send_pulse_audio_request_timeout(
                    &LinuxPulseAudioIpcRequest::StartCapture {
                        token,
                        source: String::new(),
                    },
                    PULSE_AUDIO_IPC_IO_TIMEOUT_MS,
                )
                .await
                .unwrap();
            assert!(tokio::time::timeout(
                Duration::from_secs(3),
                stream.next_pulse_audio_frame_timeout(3_000)
            )
            .await
            .unwrap()
            .is_err());
            return;
        }
        let authority = crate::audio_service::PaCaptureNativeFixture::new().unwrap();
        let mut incoming = new_listener("_pa").await.unwrap();
        let path = Config::ipc_path("_pa");

        let mut local = connect(1_000, "_pa").await.unwrap();
        local
            .send_pulse_audio_request_timeout(
                &LinuxPulseAudioIpcRequest::StartCapture {
                    token: authority.token().to_owned(),
                    source: String::new(),
                },
                PULSE_AUDIO_IPC_IO_TIMEOUT_MS,
            )
            .await
            .unwrap();
        let accepted = tokio::time::timeout(Duration::from_secs(3), incoming.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut accepted = Connection::new_pulse_audio(accepted);
        let request = accepted
            .next_pulse_audio_request_timeout(PULSE_AUDIO_IPC_IO_TIMEOUT_MS)
            .await
            .unwrap()
            .unwrap();
        let LinuxPulseAudioIpcRequest::StartCapture { token, .. } = request;
        assert_eq!(token, authority.token());
        let local_peer = validate_pulse_audio_capture_request(&accepted, &token)
            .await
            .unwrap();
        assert_eq!(local_peer.pid(), std::process::id());
        drop(accepted);
        drop(local);

        let parent_pid = unsafe { hbb_common::libc::getppid() };
        assert!(parent_pid > 0);
        std::env::set_var(crate::common::CM_LAUNCH_PARENT_ENV, parent_pid.to_string());
        assert_eq!(ipc_auth::linux_cm_owner_identity().unwrap().pid(), parent_pid as u32);

        let mut silent = tokio::process::Command::new(std::env::current_exe().unwrap());
        silent
            .args([
                "--exact",
                "ipc::pulse_audio::tests::real_kernel_pa_admission_refuses_same_uid_child_with_token",
                "--ignored",
                "--test-threads=1",
            ])
            .env("RUSTDESK_PA_NATIVE_SILENT_ATTACKER", "1")
            .env("RUSTDESK_PA_NATIVE_ATTACKER_SOCKET", &path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let silent = silent.spawn().unwrap();
        let accepted = tokio::time::timeout(Duration::from_secs(3), incoming.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_millis(750), handle_pa_stream(accepted))
            .await
            .unwrap();
        let output = tokio::time::timeout(Duration::from_secs(5), silent.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert!(
            output.status.success(),
            "silent attacker client failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let mut child = tokio::process::Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "ipc::pulse_audio::tests::real_kernel_pa_admission_refuses_same_uid_child_with_token",
                "--ignored",
                "--test-threads=1",
            ])
            .env("RUSTDESK_PA_NATIVE_ATTACKER", "1")
            .env("RUSTDESK_PA_NATIVE_ATTACKER_SOCKET", &path)
            .env("RUSTDESK_PA_NATIVE_ATTACKER_TOKEN", authority.token())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let child = child.spawn().unwrap();
        let child_pid = child.id().unwrap();
        let accepted = tokio::time::timeout(Duration::from_secs(3), incoming.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut accepted = Connection::new_pulse_audio(accepted);
        let request = accepted
            .next_pulse_audio_request_timeout(PULSE_AUDIO_IPC_IO_TIMEOUT_MS)
            .await
            .unwrap()
            .unwrap();
        let LinuxPulseAudioIpcRequest::StartCapture { token, .. } = request;
        assert_eq!(token, authority.token());
        let peer = ipc_auth::linux_kernel_peer_process_identity(&accepted, "_pa").unwrap();
        assert_eq!(peer.pid(), child_pid);
        assert_eq!(peer.uid(), local_peer.uid());
        let refused = validate_pulse_audio_capture_request(&accepted, &token)
            .await
            .unwrap_err();
        assert!(
            refused
                .to_string()
                .contains("not the connection-manager launch parent"),
            "{refused}"
        );
        drop(accepted);
        let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert!(
            output.status.success(),
            "attacker client failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        drop(incoming);
    }
}
