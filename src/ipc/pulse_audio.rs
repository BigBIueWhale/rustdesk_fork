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
    selected: Option<String>,
    monitor: Option<String>,
    done: bool,
    failed: bool,
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

    let lookup = Rc::new(RefCell::new(PaSourceLookup::default()));
    let callback_lookup = Rc::clone(&lookup);
    let requested = requested_source.to_owned();
    let introspector = context.introspect();
    let operation = introspector.get_source_info_list(move |item| {
        let mut lookup = callback_lookup.borrow_mut();
        match item {
            pulse::callbacks::ListResult::Item(info) => {
                if let Some(name) = info.name.as_ref() {
                    if name.len() > 1024 {
                        return;
                    }
                    if lookup.monitor.is_none() && name.contains("monitor") {
                        lookup.monitor = Some(name.to_string());
                    }
                    if lookup.selected.is_none()
                        && !requested.is_empty()
                        && info.description.as_deref() == Some(requested.as_str())
                    {
                        lookup.selected = Some(name.to_string());
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
        if lookup.borrow().failed {
            bail!("PulseAudio source lookup failed");
        }
        if lookup.borrow().done {
            break;
        }
        if context.get_state() != pulse::context::State::Ready {
            bail!("PulseAudio context disconnected during source lookup");
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
        lookup.selected.take().or_else(|| lookup.monitor.take())
    }
    .ok_or_else(|| anyhow::anyhow!("no PulseAudio source or monitor available"))?;

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
    recorder.connect_record(Some(&source), Some(&attr), pulse::stream::FlagSet::NOFLAGS)?;
    let deadline = Instant::now() + PA_SETUP_TIMEOUT;
    loop {
        iterate_pa(&mut mainloop)?;
        match recorder.get_state() {
            pulse::stream::State::Ready => break,
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
    log::info!("pa monitor: {:?}", source);

    let mut frames = PaCaptureFrames::default();
    loop {
        iterate_pa(&mut mainloop)?;
        if context.get_state() != pulse::context::State::Ready
            || recorder.get_state() != pulse::stream::State::Ready
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
