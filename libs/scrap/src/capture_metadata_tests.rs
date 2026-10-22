use crate::{test_allocator, PixelBuffer, Pixfmt, TraitPixelBuffer};
use std::hint::black_box;

#[test]
fn construction_needs_no_allocation() {
    let data = [0x5a; 32];
    let refusals = test_allocator::refusals();
    test_allocator::arm();
    let result = black_box(PixelBuffer::new(black_box(&data), Pixfmt::BGRA, 3, 2, 16));
    let unused = test_allocator::take_armed();
    assert!(unused);
    assert_eq!(test_allocator::refusals(), refusals);
    let pixels = result.unwrap();
    assert_eq!(pixels.data(), data);
    assert_eq!((pixels.width(), pixels.height()), (3, 2));
    assert_eq!(pixels.pixfmt(), Pixfmt::BGRA);
    println!("CAPTURE_METADATA_NATIVE=pass operation=construct stride={:?} allocations=0 pixels=exact", pixels.stride());
}

#[test]
fn stride_read_needs_no_allocation() {
    let data = [0x5a; 32];
    let pixels = PixelBuffer::new(&data, Pixfmt::BGRA, 3, 2, 16).unwrap();
    let refusals = test_allocator::refusals();
    test_allocator::arm();
    let stride = black_box(black_box(&pixels).stride());
    let unused = test_allocator::take_armed();
    assert!(unused);
    assert_eq!(test_allocator::refusals(), refusals);
    assert_eq!(pixels.data(), data);
    println!("CAPTURE_METADATA_NATIVE=pass operation=read stride={stride:?} allocations=0 pixels=exact");
}
