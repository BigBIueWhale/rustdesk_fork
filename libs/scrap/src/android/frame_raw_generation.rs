#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BeginGeneration {
    New,
    Current,
    Rejected,
}

#[derive(Default)]
pub(crate) struct FrameRawGenerationOwner {
    greatest_generation: u64,
    active_generation: Option<u64>,
}

impl FrameRawGenerationOwner {
    pub(crate) fn begin(&mut self, generation: u64) -> BeginGeneration {
        if generation == 0 {
            return BeginGeneration::Rejected;
        }
        if self.active_generation == Some(generation) {
            return BeginGeneration::Current;
        }
        if generation <= self.greatest_generation {
            return BeginGeneration::Rejected;
        }
        self.greatest_generation = generation;
        self.active_generation = Some(generation);
        BeginGeneration::New
    }

    pub(crate) fn retire(&mut self, generation: u64) -> bool {
        if generation == 0 || self.active_generation != Some(generation) {
            return false;
        }
        self.active_generation = None;
        true
    }

    pub(crate) fn admits(&self, generation: u64) -> bool {
        generation != 0 && self.active_generation == Some(generation)
    }
}

#[cfg(test)]
mod tests {
    use super::{BeginGeneration, FrameRawGenerationOwner};

    #[test]
    fn stale_generation_cannot_mutate_replacement() {
        let mut owner = FrameRawGenerationOwner::default();
        assert_eq!(owner.begin(0), BeginGeneration::Rejected);
        assert_eq!(owner.begin(7), BeginGeneration::New);
        assert_eq!(owner.begin(7), BeginGeneration::Current);
        assert!(owner.admits(7));

        assert_eq!(owner.begin(8), BeginGeneration::New);
        assert!(!owner.admits(7));
        assert!(owner.admits(8));
        assert!(!owner.retire(7));
        assert!(owner.admits(8));
    }

    #[test]
    fn exact_retirement_prevents_same_generation_reactivation() {
        let mut owner = FrameRawGenerationOwner::default();
        assert_eq!(owner.begin(12), BeginGeneration::New);
        assert!(!owner.retire(11));
        assert!(owner.admits(12));
        assert!(owner.retire(12));
        assert!(!owner.admits(12));
        assert_eq!(owner.begin(12), BeginGeneration::Rejected);

        assert_eq!(owner.begin(13), BeginGeneration::New);
        assert!(owner.admits(13));
    }

    #[test]
    fn retired_or_superseded_generations_never_regress() {
        let mut owner = FrameRawGenerationOwner::default();
        assert_eq!(owner.begin(3), BeginGeneration::New);
        assert!(owner.retire(3));
        assert_eq!(owner.begin(2), BeginGeneration::Rejected);
        assert_eq!(owner.begin(3), BeginGeneration::Rejected);
        assert_eq!(owner.begin(4), BeginGeneration::New);
        assert_eq!(owner.begin(3), BeginGeneration::Rejected);
        assert!(owner.admits(4));
    }
}
