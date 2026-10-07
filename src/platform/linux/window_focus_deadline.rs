use super::FocusError;
use std::{ffi::c_int, io, os::fd::{AsRawFd, BorrowedFd},
          sync::{mpsc, Arc, Condvar, Mutex}, thread::{self, JoinHandle}, time::{Duration, Instant}};

enum State {
    Idle,
    Armed(Instant),
    Expired(Option<io::Error>),
    Closing,
}

/// Cancels only the retained socket of one native focus connection.
pub(super) struct SocketDeadline {
    state: Arc<(Mutex<State>, Condvar)>,
    worker: Option<JoinHandle<()>>,
}

impl SocketDeadline {
    pub(super) fn new(socket: BorrowedFd<'_>) -> io::Result<Self> {
        // The worker owns a duplicate, not a reusable integer descriptor. It
        // never accesses the XCB object, and cannot shut down a replacement socket.
        let socket = socket.try_clone_to_owned()?;
        let state = Arc::new((Mutex::new(State::Idle), Condvar::new()));
        let worker_state = Arc::clone(&state);
        let (ready, started) = mpsc::sync_channel(0);
        let worker = thread::Builder::new().name("x11-focus-timer".into()).spawn(move || {
            let (mutex, changed) = &*worker_state;
            let mut state = mutex.lock().unwrap();
            if ready.send(()).is_err() {
                return;
            }
            loop {
                match *state {
                    State::Idle => state = changed.wait(state).unwrap(),
                    State::Armed(deadline) => {
                        if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                            state = changed.wait_timeout(state, remaining).unwrap().0;
                        } else {
                            // SHUT_RD wakes the sole native reader and libxcb's
                            // read/write wait without causing writes to SIGPIPE.
                            // The connection owner closes both directions after drain.
                            let result = unsafe { shutdown(socket.as_raw_fd(), 0) };
                            let error = (result != 0).then(io::Error::last_os_error);
                            *state = State::Expired(error);
                            return;
                        }
                    }
                    State::Expired(_) | State::Closing => return,
                }
            }
        })?;
        let owner = Self { state, worker: Some(worker) };
        started.recv().map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe,
            "X11 focus deadline worker did not start"))?;
        Ok(owner)
    }

    pub(super) fn start(&self, budget: Duration) -> Result<Observation<'_>, FocusError> {
        let (mutex, changed) = &*self.state;
        let mut state = mutex.lock().unwrap();
        if !matches!(*state, State::Idle) {
            return Err(FocusError::MissingReply);
        }
        *state = State::Armed(Instant::now() + budget);
        changed.notify_one();
        Ok(Observation { owner: self, finished: false })
    }
}

impl Drop for SocketDeadline {
    fn drop(&mut self) {
        let (mutex, changed) = &*self.state;
        {
            let mut state = mutex.lock().unwrap();
            if let State::Expired(Some(error)) = &*state {
                eprintln!("failed to cancel X11 focus socket: {error}");
            }
            *state = State::Closing;
            changed.notify_one();
        }
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                eprintln!("X11 focus deadline worker panicked during retirement");
            }
        }
    }
}

pub(super) struct Observation<'a> {
    owner: &'a SocketDeadline,
    finished: bool,
}

impl Observation<'_> {
    pub(super) fn finish(mut self) -> Result<(), FocusError> {
        self.finished = true;
        let (mutex, changed) = &*self.owner.state;
        let state = std::mem::replace(&mut *mutex.lock().unwrap(), State::Idle);
        changed.notify_one();
        match state {
            State::Armed(deadline) if Instant::now() < deadline => Ok(()),
            State::Armed(_) | State::Expired(None) => Err(FocusError::Deadline),
            State::Expired(Some(error)) => Err(FocusError::Transport(error)),
            State::Idle | State::Closing => Err(FocusError::MissingReply),
        }
    }
}

impl Drop for Observation<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let (mutex, changed) = &*self.owner.state;
            let mut state = mutex.lock().unwrap();
            if matches!(*state, State::Armed(_)) {
                // An unwound observation cannot leave this connection reusable.
                *state = State::Armed(Instant::now());
                changed.notify_one();
            }
        }
    }
}

extern "C" { fn shutdown(socket: c_int, how: c_int) -> c_int; }
