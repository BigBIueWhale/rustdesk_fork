#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum AndroidListenerPhase {
    #[default]
    Inactive,
    Reserved,
    Starting,
    Active,
    StopRequested,
    Exited,
}

#[derive(Default)]
pub(crate) struct AndroidListenerLifecycle {
    generation: u64,
    rebuild_epoch: u64,
    phase: AndroidListenerPhase,
}

impl AndroidListenerLifecycle {
    pub(crate) const fn new() -> Self {
        Self {
            generation: 0,
            rebuild_epoch: 0,
            phase: AndroidListenerPhase::Inactive,
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn begin_generation(&mut self) -> Option<u64> {
        if self.phase != AndroidListenerPhase::Inactive {
            return None;
        }
        let next = self.generation.checked_add(1)?;
        if next > i64::MAX as u64 {
            return None;
        }
        self.generation = next;
        self.rebuild_epoch = 0;
        self.phase = AndroidListenerPhase::Reserved;
        Some(next)
    }

    pub(crate) fn activate_generation(&mut self, expected_generation: u64) -> bool {
        if self.phase != AndroidListenerPhase::Reserved || self.generation != expected_generation {
            return false;
        }
        self.phase = AndroidListenerPhase::Starting;
        true
    }

    pub(crate) fn register_worker(&mut self, expected_generation: u64) -> bool {
        if self.phase != AndroidListenerPhase::Starting || self.generation != expected_generation {
            return false;
        }
        self.phase = AndroidListenerPhase::Active;
        true
    }

    pub(crate) fn stop_generation(&mut self, expected_generation: u64) -> bool {
        if expected_generation == 0 || self.generation != expected_generation {
            return false;
        }
        self.phase = match self.phase {
            AndroidListenerPhase::Reserved => AndroidListenerPhase::Inactive,
            AndroidListenerPhase::Starting | AndroidListenerPhase::Active => {
                AndroidListenerPhase::StopRequested
            }
            AndroidListenerPhase::StopRequested
            | AndroidListenerPhase::Exited
            | AndroidListenerPhase::Inactive => return true,
        };
        true
    }

    pub(crate) fn worker_start_failed(&mut self, expected_generation: u64) -> bool {
        if expected_generation == 0 || self.generation != expected_generation {
            return false;
        }
        match self.phase {
            AndroidListenerPhase::Starting | AndroidListenerPhase::StopRequested => {
                self.phase = AndroidListenerPhase::Inactive;
                true
            }
            AndroidListenerPhase::Inactive => true,
            AndroidListenerPhase::Reserved
            | AndroidListenerPhase::Active
            | AndroidListenerPhase::Exited => false,
        }
    }

    pub(crate) fn note_worker_exit(&mut self, expected_generation: u64) -> bool {
        if expected_generation == 0 || self.generation != expected_generation {
            return false;
        }
        match self.phase {
            AndroidListenerPhase::Starting
            | AndroidListenerPhase::Active
            | AndroidListenerPhase::StopRequested => {
                self.phase = AndroidListenerPhase::Exited;
                true
            }
            AndroidListenerPhase::Exited => true,
            AndroidListenerPhase::Inactive | AndroidListenerPhase::Reserved => false,
        }
    }

    pub(crate) fn confirm_worker_converged(&mut self, expected_generation: u64) -> bool {
        if expected_generation == 0 || self.generation != expected_generation {
            return false;
        }
        match self.phase {
            AndroidListenerPhase::Exited => {
                self.phase = AndroidListenerPhase::Inactive;
                true
            }
            AndroidListenerPhase::Inactive => true,
            AndroidListenerPhase::Reserved
            | AndroidListenerPhase::Starting
            | AndroidListenerPhase::Active
            | AndroidListenerPhase::StopRequested => false,
        }
    }

    pub(crate) fn request_rebuild(&mut self, expected_generation: u64) -> Option<u64> {
        if self.phase != AndroidListenerPhase::Active
            || expected_generation == 0
            || self.generation != expected_generation
        {
            return None;
        }
        let Some(next) = self.rebuild_epoch.checked_add(1) else {
            self.phase = AndroidListenerPhase::StopRequested;
            return None;
        };
        self.rebuild_epoch = next;
        Some(next)
    }

    pub(crate) fn snapshot(&self, expected_generation: u64) -> Option<u64> {
        (self.phase == AndroidListenerPhase::Active
            && expected_generation != 0
            && self.generation == expected_generation)
            .then_some(self.rebuild_epoch)
    }

    #[cfg(test)]
    fn is_exact_inactive(&self, expected_generation: u64) -> bool {
        expected_generation != 0
            && self.generation == expected_generation
            && self.phase == AndroidListenerPhase::Inactive
    }
}

#[cfg(test)]
mod tests {
    use super::{AndroidListenerLifecycle, AndroidListenerPhase};

    #[test]
    fn stale_network_callback_cannot_advance_replacement_generation_epoch() {
        let mut lifecycle = AndroidListenerLifecycle::new();

        let first = lifecycle.begin_generation().unwrap();
        assert_eq!(lifecycle.generation(), first);
        assert_eq!(lifecycle.snapshot(first), None);
        assert!(lifecycle.activate_generation(first));
        assert_eq!(lifecycle.snapshot(first), None);
        assert!(lifecycle.register_worker(first));
        assert_eq!(lifecycle.snapshot(first), Some(0));
        assert_eq!(lifecycle.request_rebuild(first), Some(1));
        assert_eq!(lifecycle.snapshot(first), Some(1));
        assert_eq!(lifecycle.begin_generation(), None);

        assert!(!lifecycle.stop_generation(first + 1));
        assert_eq!(lifecycle.snapshot(first), Some(1));
        assert!(lifecycle.stop_generation(first));
        assert_eq!(lifecycle.phase, AndroidListenerPhase::StopRequested);
        assert_eq!(lifecycle.begin_generation(), None);
        assert!(!lifecycle.is_exact_inactive(first));

        assert!(lifecycle.note_worker_exit(first));
        assert_eq!(lifecycle.phase, AndroidListenerPhase::Exited);
        assert_eq!(lifecycle.begin_generation(), None);
        assert!(lifecycle.confirm_worker_converged(first));
        assert!(lifecycle.is_exact_inactive(first));

        let replacement = lifecycle.begin_generation().unwrap();
        assert!(replacement > first);
        assert!(lifecycle.activate_generation(replacement));
        assert!(lifecycle.register_worker(replacement));
        assert_eq!(lifecycle.request_rebuild(replacement), Some(1));

        assert_eq!(lifecycle.request_rebuild(first), None);
        assert_eq!(lifecycle.snapshot(replacement), Some(1));
        assert!(!lifecycle.stop_generation(first));
        assert_eq!(lifecycle.snapshot(replacement), Some(1));
    }

    #[test]
    fn worker_must_be_registered_and_converged_before_replacement() {
        let mut lifecycle = AndroidListenerLifecycle::default();
        let generation = lifecycle.begin_generation().unwrap();

        assert!(lifecycle.activate_generation(generation));
        assert_eq!(lifecycle.phase, AndroidListenerPhase::Starting);
        assert_eq!(lifecycle.snapshot(generation), None);
        assert_eq!(lifecycle.begin_generation(), None);

        assert!(lifecycle.register_worker(generation));
        assert_eq!(lifecycle.phase, AndroidListenerPhase::Active);
        assert!(!lifecycle.register_worker(generation));
        assert!(lifecycle.stop_generation(generation));
        assert!(lifecycle.stop_generation(generation));
        assert_eq!(lifecycle.phase, AndroidListenerPhase::StopRequested);
        assert_eq!(lifecycle.begin_generation(), None);

        assert!(lifecycle.note_worker_exit(generation));
        assert_eq!(lifecycle.phase, AndroidListenerPhase::Exited);
        assert_eq!(lifecycle.begin_generation(), None);
        assert!(lifecycle.confirm_worker_converged(generation));
        assert_eq!(lifecycle.phase, AndroidListenerPhase::Inactive);
        assert!(lifecycle.begin_generation().is_some());
    }

    #[test]
    fn invalid_exhausted_and_thread_creation_failure_edges_fail_closed() {
        let mut lifecycle = AndroidListenerLifecycle::default();
        assert_eq!(lifecycle.request_rebuild(0), None);
        assert!(!lifecycle.stop_generation(0));

        let reserved = lifecycle.begin_generation().unwrap();
        assert!(!lifecycle.activate_generation(reserved + 1));
        assert!(lifecycle.stop_generation(reserved));
        assert!(lifecycle.is_exact_inactive(reserved));

        lifecycle.generation = i64::MAX as u64;
        lifecycle.phase = AndroidListenerPhase::Inactive;
        assert_eq!(lifecycle.begin_generation(), None);

        lifecycle.generation = 7;
        lifecycle.rebuild_epoch = u64::MAX;
        lifecycle.phase = AndroidListenerPhase::Active;
        assert_eq!(lifecycle.request_rebuild(7), None);
        assert_eq!(lifecycle.phase, AndroidListenerPhase::StopRequested);
        assert!(!lifecycle.is_exact_inactive(7));
        assert!(lifecycle.note_worker_exit(7));
        assert!(lifecycle.confirm_worker_converged(7));

        lifecycle.generation = 9;
        lifecycle.phase = AndroidListenerPhase::Reserved;
        assert!(lifecycle.activate_generation(9));
        assert!(!lifecycle.worker_start_failed(10));
        assert!(lifecycle.worker_start_failed(9));
        assert!(lifecycle.is_exact_inactive(9));
        assert!(!lifecycle.note_worker_exit(9));
    }
}
