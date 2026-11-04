use super::*;
use tokio::net::UnixStream;

fn pair() -> (ConnectionTmpl<UnixStream>, ConnectionTmpl<UnixStream>) {
    let (left, right) = UnixStream::pair().unwrap();
    (
        ConnectionTmpl::new_protected_service(left),
        ConnectionTmpl::new_protected_service(right),
    )
}

#[tokio::test(flavor = "current_thread")]
async fn credential_requests_round_trip() {
    let (mut sender, mut receiver) = pair();
    for request in [
        WindowsServiceCredentialRequest::QuiesceCredentialReplica {
            transition_id: "first".into(),
        },
        WindowsServiceCredentialRequest::ApplyCredentialReplica {
            transition_id: "second".into(),
            storage: "opaque fixture\n\"value\"".into(),
            salt: "salt fixture".into(),
            replica_tag: [0x55; 32],
        },
        WindowsServiceCredentialRequest::QueryCredentialReplica,
        WindowsServiceCredentialRequest::ResumeCredentialReplica {
            transition_id: "third".into(),
        },
    ] {
        sender.send_windows_service_credential_request_timeout(&request, 500).await.unwrap();
        let received = receiver.next_windows_service_credential_request_timeout(500).await.unwrap();
        assert_eq!(received.as_ref(), Some(&request));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn control_requests_round_trip() {
    let (mut sender, mut receiver) = pair();
    for request in [WindowsServiceControlRequest::PortForwardSessionCount,
                    WindowsServiceControlRequest::Shutdown] {
        sender.send_windows_service_control_request_timeout(&request, 500).await.unwrap();
        assert_eq!(receiver.next_windows_service_control_request_timeout(500).await.unwrap(),
                   Some(request));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn responses_round_trip() {
    let (mut sender, mut receiver) = pair();
    for response in [
        WindowsServiceCredentialResponse::Rejected,
        WindowsServiceCredentialResponse::State(WindowsCredentialReplicaState {
            transition_id: None, replica_tag: [0; 32], quiesced: false,
        }),
        WindowsServiceCredentialResponse::State(WindowsCredentialReplicaState {
            transition_id: Some("transition".into()), replica_tag: [0xff; 32], quiesced: true,
        }),
    ] {
        sender.send_windows_service_credential_response_timeout(&response, 500).await.unwrap();
        let received = receiver.next_windows_service_credential_response_timeout(500).await.unwrap();
        assert_eq!(received.as_ref(), Some(&response));
    }
    let (mut sender, mut receiver) = pair();
    for response in [WindowsServiceControlResponse::PortForwardSessionCount(0),
                     WindowsServiceControlResponse::PortForwardSessionCount(usize::MAX),
                     WindowsServiceControlResponse::ShutdownAccepted] {
        sender.send_windows_service_control_response_timeout(&response, 500).await.unwrap();
        assert_eq!(receiver.next_windows_service_control_response_timeout(500).await.unwrap(),
                   Some(response));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn readers_refuse_other_endpoint_and_direction() {
    macro_rules! refuse {
        ($send:ident, $value:expr, $read:ident) => {{
            let (mut sender, mut receiver) = pair();
            sender.$send(&$value, 500).await.unwrap();
            assert!(receiver.$read(500).await.unwrap().is_none());
        }};
    }
    let credential_request = WindowsServiceCredentialRequest::QueryCredentialReplica;
    let credential_response = WindowsServiceCredentialResponse::Rejected;
    let control_request = WindowsServiceControlRequest::PortForwardSessionCount;
    let control_response = WindowsServiceControlResponse::PortForwardSessionCount(7);
    refuse!(send_windows_service_credential_request_timeout, credential_request, next_windows_service_credential_response_timeout);
    refuse!(send_windows_service_credential_request_timeout, credential_request, next_windows_service_control_request_timeout);
    refuse!(send_windows_service_credential_request_timeout, credential_request, next_windows_service_control_response_timeout);
    refuse!(send_windows_service_credential_response_timeout, credential_response, next_windows_service_credential_request_timeout);
    refuse!(send_windows_service_credential_response_timeout, credential_response, next_windows_service_control_request_timeout);
    refuse!(send_windows_service_credential_response_timeout, credential_response, next_windows_service_control_response_timeout);
    refuse!(send_windows_service_control_request_timeout, control_request, next_windows_service_control_response_timeout);
    refuse!(send_windows_service_control_request_timeout, control_request, next_windows_service_credential_request_timeout);
    refuse!(send_windows_service_control_request_timeout, control_request, next_windows_service_credential_response_timeout);
    refuse!(send_windows_service_control_response_timeout, control_response, next_windows_service_control_request_timeout);
    refuse!(send_windows_service_control_response_timeout, control_response, next_windows_service_credential_request_timeout);
    refuse!(send_windows_service_control_response_timeout, control_response, next_windows_service_credential_response_timeout);
}

#[tokio::test(flavor = "current_thread")]
async fn typed_methods_preserve_frame_budget() {
    assert_eq!(SERVICE_IPC_MAX_FRAME_BYTES, 32 * 1024);
    let (mut sender, mut receiver) = pair();
    let mut request = WindowsServiceCredentialRequest::ApplyCredentialReplica {
        transition_id: "transition".into(), storage: String::new(), salt: "salt".into(),
        replica_tag: [0; 32],
    };
    let size = serde_json::to_vec(&request).unwrap().len();
    if let WindowsServiceCredentialRequest::ApplyCredentialReplica { storage, .. } = &mut request {
        *storage = "a".repeat(SERVICE_IPC_MAX_FRAME_BYTES - size);
    }
    assert_eq!(serde_json::to_vec(&request).unwrap().len(), SERVICE_IPC_MAX_FRAME_BYTES);
    sender.send_windows_service_credential_request_timeout(&request, 500).await.unwrap();
    assert_eq!(receiver.next_windows_service_credential_request_timeout(500).await.unwrap().as_ref(), Some(&request));
    if let WindowsServiceCredentialRequest::ApplyCredentialReplica { storage, .. } = &mut request {
        storage.push('a');
    }
    assert!(sender.send_windows_service_credential_request_timeout(&request, 500).await.is_err());
    sender.send_windows_service_credential_request_timeout(&WindowsServiceCredentialRequest::QueryCredentialReplica, 500).await.unwrap();
    assert_eq!(receiver.next_windows_service_credential_request_timeout(500).await.unwrap(), Some(WindowsServiceCredentialRequest::QueryCredentialReplica));

    let mut state = WindowsCredentialReplicaState {
        transition_id: Some(String::new()), replica_tag: [0; 32], quiesced: false,
    };
    let size = serde_json::to_vec(&WindowsServiceCredentialResponse::State(state.clone())).unwrap().len();
    state.transition_id = Some("a".repeat(SERVICE_IPC_MAX_FRAME_BYTES - size));
    let response = WindowsServiceCredentialResponse::State(state.clone());
    assert_eq!(serde_json::to_vec(&response).unwrap().len(), SERVICE_IPC_MAX_FRAME_BYTES);
    sender.send_windows_service_credential_response_timeout(&response, 500).await.unwrap();
    assert_eq!(receiver.next_windows_service_credential_response_timeout(500).await.unwrap(), Some(response));
    state.transition_id.as_mut().unwrap().push('a');
    assert!(sender.send_windows_service_credential_response_timeout(&WindowsServiceCredentialResponse::State(state), 500).await.is_err());
    sender.send_windows_service_credential_response_timeout(&WindowsServiceCredentialResponse::Rejected, 500).await.unwrap();
    assert_eq!(receiver.next_windows_service_credential_response_timeout(500).await.unwrap(), Some(WindowsServiceCredentialResponse::Rejected));

    macro_rules! oversized {
        ($read:ident) => {{
            let (left, right) = UnixStream::pair().unwrap();
            let mut sender = ConnectionTmpl::new(left);
            let mut receiver = ConnectionTmpl::new_protected_service(right);
            sender.send_raw(Bytes::from(vec![b'x'; SERVICE_IPC_MAX_FRAME_BYTES + 1])).await.unwrap();
            assert_eq!(receiver.$read(500).await.unwrap_err().to_string(), "Too big packet");
        }};
    }
    oversized!(next_windows_service_credential_request_timeout);
    oversized!(next_windows_service_credential_response_timeout);
    oversized!(next_windows_service_control_request_timeout);
    oversized!(next_windows_service_control_response_timeout);
}

#[tokio::test(flavor = "current_thread")]
async fn typed_reads_report_deadline_and_peer_exit() {
    macro_rules! deadline_and_exit {
        ($read:ident) => {{
            let (sender, mut receiver) = pair();
            let error = receiver.$read(20).await.unwrap_err();
            assert!(error.downcast_ref::<tokio::time::error::Elapsed>().is_some());
            drop(sender);
            assert_eq!(receiver.$read(500).await.unwrap_err().to_string(), "reset by the peer");
        }};
    }
    deadline_and_exit!(next_windows_service_credential_request_timeout);
    deadline_and_exit!(next_windows_service_credential_response_timeout);
    deadline_and_exit!(next_windows_service_control_request_timeout);
    deadline_and_exit!(next_windows_service_control_response_timeout);
}
