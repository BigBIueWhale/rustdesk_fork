use std::ptr::NonNull;

/// One thread-owned native context and its matching retirement operation.
pub(super) struct NativeContext<T> {
    pointer: NonNull<T>,
    retire: unsafe fn(*mut T),
}

impl<T> NativeContext<T> {
    /// Takes ownership of a native constructor's result, if it is non-null.
    ///
    /// # Safety
    /// The pointer must be uniquely owned and valid for `retire`. No other owner
    /// may retire it, and `retire` must remain callable until this value drops.
    pub(super) unsafe fn from_raw(pointer: *mut T, retire: unsafe fn(*mut T)) -> Option<Self> {
        NonNull::new(pointer).map(|pointer| Self { pointer, retire })
    }

    pub(super) fn as_ptr(&self) -> *mut T {
        self.pointer.as_ptr()
    }
}

impl<T> Drop for NativeContext<T> {
    fn drop(&mut self) {
        unsafe { (self.retire)(self.pointer.as_ptr()) };
    }
}
