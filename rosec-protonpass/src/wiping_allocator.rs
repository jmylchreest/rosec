//! Wipe Rust-owned guest heap allocations before returning them to the allocator.
//! Extism transport memory is owned by the host and is scrubbed separately.
use std::alloc::{GlobalAlloc, Layout};
use zeroize::Zeroize;

pub struct WipingAllocator<A>(pub A);

// SAFETY: allocation is delegated with the original layout. Deallocation writes
// only within that live allocation before forwarding it with the same layout.
unsafe impl<A: GlobalAlloc> GlobalAlloc for WipingAllocator<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { std::slice::from_raw_parts_mut(ptr, layout.size()) }.zeroize();
        unsafe { self.0.dealloc(ptr, layout) };
    }
    // The default realloc allocates, copies, then calls our wiping dealloc.
    // Delegating realloc would leave the old allocation unscrubbed on growth.
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::System;

    struct Checked;
    unsafe impl GlobalAlloc for Checked {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            assert!(
                unsafe { std::slice::from_raw_parts(ptr, layout.size()) }
                    .iter()
                    .all(|b| *b == 0)
            );
            unsafe { System.dealloc(ptr, layout) };
        }
    }

    #[test]
    fn wipes_freed_and_reallocated_storage() {
        let allocator = WipingAllocator(Checked);
        unsafe {
            let layout = Layout::from_size_align(64, 8).unwrap();
            let ptr = allocator.alloc(layout);
            assert!(!ptr.is_null());
            ptr.write_bytes(0xab, 64);
            let larger = allocator.realloc(ptr, layout, 128);
            assert!(!larger.is_null());
            assert_eq!(std::slice::from_raw_parts(larger, 64), &[0xab; 64]);
            allocator.dealloc(larger, Layout::from_size_align(128, 8).unwrap());
        }
    }
}
