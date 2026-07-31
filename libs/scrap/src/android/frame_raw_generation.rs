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

#[derive(Default)]
pub(crate) struct GenerationOwnedScreenSize {
    owner: FrameRawGenerationOwner,
    size: Option<(u16, u16, u16)>,
}

impl GenerationOwnedScreenSize {
    pub(crate) fn begin_generation(&mut self, generation: u64) -> bool {
        match self.owner.begin(generation) {
            BeginGeneration::New => {
                self.size = None;
                true
            }
            BeginGeneration::Current => true,
            BeginGeneration::Rejected => false,
        }
    }

    pub(crate) fn retire_generation(&mut self, generation: u64) -> bool {
        if !self.owner.retire(generation) {
            return false;
        }
        self.size = None;
        true
    }

    pub(crate) fn update(&mut self, generation: u64, size: (u16, u16, u16)) -> bool {
        if !self.owner.admits(generation) || size.0 == 0 || size.1 == 0 || !matches!(size.2, 1 | 2)
        {
            return false;
        }
        self.size = Some(size);
        true
    }

    pub(crate) fn get(&self, generation: u64) -> Option<(u16, u16, u16)> {
        self.owner.admits(generation).then_some(self.size).flatten()
    }

    pub(crate) fn current(&self) -> Option<(u16, u16, u16)> {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::{BeginGeneration, FrameRawGenerationOwner, GenerationOwnedScreenSize};

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

    #[test]
    fn screen_size_is_visible_only_to_its_exact_active_generation() {
        let mut screen = GenerationOwnedScreenSize::default();
        assert!(!screen.update(0, (1920, 1080, 1)));
        assert!(screen.begin_generation(7));
        assert!(screen.update(7, (1920, 1080, 1)));
        assert_eq!(screen.get(7), Some((1920, 1080, 1)));

        assert!(screen.begin_generation(8));
        assert_eq!(screen.get(7), None);
        assert_eq!(screen.get(8), None);
        assert!(!screen.update(7, (1280, 720, 2)));
        assert!(screen.update(8, (1280, 720, 2)));
        assert_eq!(screen.get(8), Some((1280, 720, 2)));
    }

    #[test]
    fn screen_size_retirement_and_reactivation_fail_closed() {
        let mut screen = GenerationOwnedScreenSize::default();
        assert!(screen.begin_generation(12));
        assert!(screen.update(12, (2560, 1440, 1)));
        assert!(!screen.retire_generation(11));
        assert_eq!(screen.get(12), Some((2560, 1440, 1)));
        assert!(screen.retire_generation(12));
        assert_eq!(screen.current(), None);
        assert!(!screen.begin_generation(12));
        assert!(!screen.update(12, (2560, 1440, 1)));
    }
}
