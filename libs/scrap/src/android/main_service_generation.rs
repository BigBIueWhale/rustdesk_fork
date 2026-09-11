#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ListenerState {
    Inactive,
    Reserved,
    ActivationClaimed,
}

pub(crate) struct MainServiceGenerationState {
    generation: Option<u64>,
    last_retired_generation: Option<u64>,
    listener_state: ListenerState,
}

impl Default for MainServiceGenerationState {
    fn default() -> Self {
        Self {
            generation: None,
            last_retired_generation: None,
            listener_state: ListenerState::Inactive,
        }
    }
}

impl MainServiceGenerationState {
    pub(crate) fn has_generation(&self) -> bool {
        self.generation.is_some()
    }

    pub(crate) fn begin(&mut self, generation: u64) -> bool {
        if generation == 0
            || self.generation.is_some()
            || self.listener_state != ListenerState::Inactive
            || self
                .last_retired_generation
                .is_some_and(|retired| generation <= retired)
        {
            return false;
        }
        self.generation = Some(generation);
        self.listener_state = ListenerState::Reserved;
        true
    }

    pub(crate) fn claim_activation(&mut self, generation: u64) -> bool {
        if self.generation != Some(generation) || self.listener_state != ListenerState::Reserved {
            return false;
        }
        self.listener_state = ListenerState::ActivationClaimed;
        true
    }

    pub(crate) fn is_activation_claimed(&self, generation: u64) -> bool {
        self.generation == Some(generation)
            && self.listener_state == ListenerState::ActivationClaimed
    }

    pub(crate) fn is_current(&self, generation: u64) -> bool {
        generation != 0 && self.generation == Some(generation)
    }

    pub(crate) fn confirm_deactivated(&mut self, generation: u64) -> bool {
        if self.is_retired(generation) {
            return true;
        }
        if !self.is_current(generation) {
            return false;
        }
        self.listener_state = ListenerState::Inactive;
        true
    }

    pub(crate) fn can_finalize(&self, generation: u64) -> bool {
        self.is_current(generation) && self.listener_state == ListenerState::Inactive
    }

    pub(crate) fn complete_retirement(&mut self, generation: u64) -> bool {
        if self.is_retired(generation) {
            return true;
        }
        if !self.can_finalize(generation) {
            return false;
        }
        self.generation = None;
        self.last_retired_generation = Some(generation);
        true
    }

    pub(crate) fn is_retired(&self, generation: u64) -> bool {
        generation != 0
            && self.generation.is_none()
            && self.last_retired_generation == Some(generation)
            && self.listener_state == ListenerState::Inactive
    }

    pub(crate) fn may_release_callback_owner(&self) -> bool {
        self.generation.is_none() && self.listener_state == ListenerState::Inactive
    }
}

#[cfg(test)]
mod tests {
    use super::MainServiceGenerationState;

    #[test]
    fn cleanup_failure_retains_exact_generation_until_completion() {
        let mut state = MainServiceGenerationState::default();
        assert!(!state.begin(0));
        assert!(state.begin(7));
        assert!(state.has_generation());
        assert!(!state.begin(8));
        assert!(state.claim_activation(7));
        assert!(!state.claim_activation(7));
        assert!(state.is_activation_claimed(7));

        // A failed listener stop does not call confirm_deactivated, so neither finalization nor
        // callback-owner release can proceed and a replacement remains blocked.
        assert!(!state.can_finalize(7));
        assert!(!state.complete_retirement(7));
        assert!(!state.may_release_callback_owner());
        assert!(!state.begin(8));

        assert!(!state.confirm_deactivated(6));
        assert!(state.confirm_deactivated(7));
        assert!(state.can_finalize(7));
        assert!(!state.complete_retirement(6));
        assert!(state.complete_retirement(7));
        assert!(!state.has_generation());
        assert!(state.is_retired(7));
        assert!(state.may_release_callback_owner());
    }

    #[test]
    fn exact_retirement_is_idempotent_but_cannot_select_replacement() {
        let mut state = MainServiceGenerationState::default();
        assert!(state.begin(11));
        assert!(state.confirm_deactivated(11));
        assert!(state.complete_retirement(11));
        assert!(state.confirm_deactivated(11));
        assert!(state.complete_retirement(11));
        assert!(!state.begin(11));

        assert!(state.begin(12));
        assert!(!state.confirm_deactivated(11));
        assert!(!state.complete_retirement(11));
        assert!(state.is_current(12));
        assert!(!state.may_release_callback_owner());
    }
}
