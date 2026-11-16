use p256::{elliptic_curve::{hash2curve::{ExpandMsgXmd, GroupDigest}, sec1::ToEncodedPoint}, NistP256};
use sha2::Sha256;

/// RFC 9380 P256_XMD:SHA-256_SSWU_RO_ mapping with caller-supplied DST.
/// Returns 33 SEC1 compressed bytes. No private scalar crosses this boundary.
#[no_mangle]
pub unsafe extern "C" fn cx_p256_h2g(
    input: *const u8, input_len: usize, dst: *const u8, dst_len: usize, out: *mut u8,
) -> i32 {
    if input.is_null() || dst.is_null() || out.is_null() || dst_len == 0 { return -1; }
    let input = std::slice::from_raw_parts(input, input_len);
    let dst = std::slice::from_raw_parts(dst, dst_len);
    match NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[input], &[dst]) {
        Ok(point) => {
            let encoded = point.to_affine().to_encoded_point(true);
            if encoded.as_bytes().len() != 33 { return -2; }
            std::ptr::copy_nonoverlapping(encoded.as_bytes().as_ptr(), out, 33);
            0
        }
        Err(_) => -3,
    }
}
