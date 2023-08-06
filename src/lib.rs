//#![feature(maybe_uninit_slice)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

//use std::mem::MaybeUninit;

#[non_exhaustive]
#[derive(Clone, Debug, Copy)]
pub struct Sodium;

impl Sodium {
    pub fn new() -> Result<Self, ()> {
        if unsafe { ffi::sodium_init() } < 0 {
            Err(())
        } else {
            Ok(Self)
        }
    }

    pub fn crypto_generichash<'a>(
        self,
        input: &[u8],
        key: Option<&[u8]>,
        out: &'a mut [MaybeUninit<u8>],
    ) -> Result<&'a [u8], ()> {
        assert!(out.len() >= ffi::crypto_generichash_BYTES_MIN as usize);
        assert!(out.len() <= ffi::crypto_generichash_BYTES_MAX as usize);
        if let Some(key) = key {
            assert!(key.len() >= ffi::crypto_generichash_KEYBYTES_MIN as usize);
            assert!(key.len() <= ffi::crypto_generichash_KEYBYTES_MAX as usize);
        }

        let (key, keylen) = if let Some(key) = key {
            (key.as_ptr(), key.len())
        } else {
            (std::ptr::null(), 0)
        };

        let res = unsafe {
            ffi::crypto_generichash(
                MaybeUninit::slice_as_mut_ptr(out),
                out.len(),
                input.as_ptr(),
                input.len() as u64,
                key,
                keylen,
            )
        };
        if res < 0 {
            return Err(());
        }
        Ok(unsafe { MaybeUninit::slice_assume_init_mut(out) })
    }
}

pub use ffi::sodium_init;

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::MaybeUninit;

    #[test]
    fn check_sodium_init() {
        let sodium = Sodium::new();
        assert!(sodium.is_ok())
    }

    #[test]
    fn check_hash() {
        let sodium = Sodium::new().unwrap();
        let input = b"Arbitrary data to hash in Rust";
        println!("{}\n", ffi::crypto_generichash_BYTES);
        let mut out = [MaybeUninit::uninit(); ffi::crypto_generichash_BYTES as usize];
        let res = sodium.crypto_generichash(input, None, &mut out).unwrap();
        println!("{:?}\n", hex::encode(res));
    }
}
