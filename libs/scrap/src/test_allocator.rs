use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static FAIL_NEXT: Cell<bool> = const { Cell::new(false) };
    static REFUSALS: Cell<usize> = const { Cell::new(0) };
}

pub(crate) fn arm() {
    FAIL_NEXT.with(|flag| flag.set(true));
}

pub(crate) fn take_armed() -> bool {
    FAIL_NEXT.with(|flag| flag.replace(false))
}

pub(crate) fn refusals() -> usize {
    REFUSALS.with(Cell::get)
}

struct RefusingAllocator;

fn refuse_allocation() -> bool {
    let refuse = FAIL_NEXT.try_with(|flag| flag.replace(false)).unwrap_or(false);
    if refuse {
        REFUSALS.with(|count| count.set(count.get() + 1));
        let marker = b"\nVIDEO_ALLOCATOR=refused\n";
        // The allocator must not allocate while reporting the injected refusal.
        if unsafe { crate::libc::write(1, marker.as_ptr().cast(), marker.len()) } != marker.len() as isize {
            unsafe { crate::libc::_exit(97) };
        }
    }
    refuse
}

unsafe impl GlobalAlloc for RefusingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if refuse_allocation() { std::ptr::null_mut() } else { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if refuse_allocation() { std::ptr::null_mut() } else { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if refuse_allocation() { std::ptr::null_mut() } else { System.realloc(pointer, layout, size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout);
    }
}

#[global_allocator]
static ALLOCATOR: RefusingAllocator = RefusingAllocator;
