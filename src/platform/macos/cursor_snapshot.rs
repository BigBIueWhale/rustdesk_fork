pub(crate) struct CursorSnapshot<T> {
    current: Option<(i32, T)>,
}

impl<T> Default for CursorSnapshot<T> {
    fn default() -> Self {
        Self { current: None }
    }
}

impl<T> CursorSnapshot<T> {
    pub(crate) fn refresh<E>(
        &mut self,
        seed: i32,
        capture: impl FnOnce(u64) -> Result<T, E>,
    ) -> Result<u64, E> {
        let id = u64::from(seed as u32);
        if self.current.as_ref().map_or(false, |(current, _)| *current == seed) {
            return Ok(id);
        }
        self.clear();
        let image = capture(id)?;
        self.current = Some((seed, image));
        Ok(id)
    }

    pub(crate) fn get(&self, id: u64) -> Option<&T> {
        self.current.as_ref()
            .filter(|(seed, _)| u64::from(*seed as u32) == id)
            .map(|(_, image)| image)
    }

    pub(crate) fn clear(&mut self) {
        self.current = None;
    }
}

#[cfg(test)]
mod tests {
    use super::CursorSnapshot;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

    struct Image(Arc<AtomicUsize>, Vec<u8>);
    impl Drop for Image {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn initial_zero_seed_and_unchanged_seed_keep_one_image() {
        let mut snapshot = CursorSnapshot::default();
        let id = snapshot.refresh(0, |id| Ok::<_, ()>((id, vec![1, 2, 3, 4]))).unwrap();
        assert_eq!(id, 0);
        assert_eq!(snapshot.get(id), Some(&(0, vec![1, 2, 3, 4])));
        assert_eq!(snapshot.refresh(0, |_| Err("must not recapture")), Ok(id));
        assert_eq!(snapshot.get(id), Some(&(0, vec![1, 2, 3, 4])));
        assert!(snapshot.get(id + 1).is_none());
    }

    #[test]
    fn failed_capture_does_not_remember_the_seed_or_return_old_pixels() {
        let retired = Arc::new(AtomicUsize::new(0));
        let mut snapshot = CursorSnapshot::default();
        snapshot.refresh(1, |_| Ok::<_, ()>(Image(retired.clone(), vec![1]))).unwrap();
        assert_eq!(snapshot.refresh(2, |_| Err("native capture failed")), Err("native capture failed"));
        assert_eq!(retired.load(Ordering::SeqCst), 1);
        assert!(snapshot.get(1).is_none() && snapshot.get(2).is_none());
        let id = snapshot.refresh(2, |_| Ok::<_, ()>(Image(retired.clone(), vec![2]))).unwrap();
        assert_eq!(id, 2);
        assert_eq!(snapshot.get(id).unwrap().1, vec![2]);
        snapshot.clear();
        snapshot.clear();
        assert!(snapshot.get(id).is_none());
        assert_eq!(retired.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn captured_pixels_survive_later_source_change_and_publication_retry() {
        let mut snapshot = CursorSnapshot::default();
        let mut source = vec![1, 2, 3, 4];
        let id = snapshot.refresh(9, |_| Ok::<_, ()>(source.clone())).unwrap();
        source.fill(8);
        assert_eq!(snapshot.get(id), Some(&vec![1, 2, 3, 4]));
        assert_eq!(snapshot.refresh(9, |_| Err("publication retry must reuse capture")), Ok(id));
        assert_eq!(snapshot.get(id), Some(&vec![1, 2, 3, 4]));
        snapshot.refresh(10, |_| Ok::<_, ()>(source)).unwrap();
        assert!(snapshot.get(id).is_none());
        assert_eq!(snapshot.get(10), Some(&vec![8; 4]));
    }

    #[test]
    fn capture_unwind_leaves_no_published_seed_or_image() {
        let mut snapshot = CursorSnapshot::default();
        snapshot.refresh(3, |_| Ok::<_, ()>(vec![3])).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            snapshot.refresh(4, |_| -> Result<Vec<u8>, ()> { panic!("capture unwind") })
        }));
        assert!(result.is_err());
        assert!(snapshot.get(3).is_none() && snapshot.get(4).is_none());
        assert_eq!(snapshot.refresh(4, |_| Ok::<_, ()>(vec![4])), Ok(4));
    }

    #[test]
    fn signed_seed_identity_replacement_and_worker_exit_retire_exactly() {
        let retired = Arc::new(AtomicUsize::new(0));
        let worker_retired = retired.clone();
        std::thread::spawn(move || {
            let mut snapshot = CursorSnapshot::default();
            let first = snapshot.refresh(-1, |_| Ok::<_, ()>(Image(worker_retired.clone(), vec![1]))).unwrap();
            assert_eq!(first, u64::from(u32::MAX));
            assert!(snapshot.get(u64::MAX).is_none());
            let next = snapshot.refresh(i32::MIN, |_| Ok::<_, ()>(Image(worker_retired.clone(), vec![2]))).unwrap();
            assert_eq!(next, 1 << 31);
            assert!(snapshot.get(first).is_none());
            assert_eq!(worker_retired.load(Ordering::SeqCst), 1);
            assert_eq!(snapshot.get(next).unwrap().1, vec![2]);
        }).join().unwrap();
        assert_eq!(retired.load(Ordering::SeqCst), 2);
    }
}
