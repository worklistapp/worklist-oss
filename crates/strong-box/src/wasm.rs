#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "strong_box")]
unsafe extern "C" {
	fn strong_box_random(ptr: *mut u8, len: usize);
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn fill_random(bytes: &mut [u8]) {
	if bytes.is_empty() {
		return;
	}

	unsafe {
		strong_box_random(bytes.as_mut_ptr(), bytes.len());
	}
}
