#[inline]
pub fn would_block_if_equal(old: &mut Vec<u8>, b: &[u8]) -> std::io::Result<()> {
    if b == &old[..] {
        return Err(std::io::ErrorKind::WouldBlock.into());
    }
    old.resize(b.len(), 0);
    old.copy_from_slice(b);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::would_block_if_equal;
    use std::io::ErrorKind;

    #[test]
    fn changed_frames_replace_the_complete_cache() {
        let mut old = vec![1, 2, 3];
        for data in [&[4, 5, 6][..], &[7, 8, 9, 10][..], &[11][..]] {
            would_block_if_equal(&mut old, data).unwrap();
            assert_eq!(old, data);
        }
    }

    #[test]
    fn equal_frames_preserve_the_cache_and_allocation() {
        let mut old = Vec::with_capacity(32);
        old.extend_from_slice(&[1, 2, 3]);
        let pointer = old.as_ptr();
        let capacity = old.capacity();
        let error = would_block_if_equal(&mut old, &[1, 2, 3]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::WouldBlock);
        assert_eq!(old, [1, 2, 3]);
        assert_eq!(old.as_ptr(), pointer);
        assert_eq!(old.capacity(), capacity);
    }

    #[test]
    fn empty_frames_follow_the_same_equality_and_replacement_rules() {
        let mut old = Vec::new();
        assert_eq!(would_block_if_equal(&mut old, &[]).unwrap_err().kind(),
                   ErrorKind::WouldBlock);
        would_block_if_equal(&mut old, &[1]).unwrap();
        would_block_if_equal(&mut old, &[]).unwrap();
        assert!(old.is_empty());
        assert_eq!(would_block_if_equal(&mut old, &[]).unwrap_err().kind(),
                   ErrorKind::WouldBlock);
    }
}
