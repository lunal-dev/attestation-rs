use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};
use sha2::{Digest, Sha256, Sha384};

/// Pad report_data to exactly `target_len` bytes.
/// Errors if input exceeds `target_len`.
pub fn pad_report_data(data: &[u8], target_len: usize) -> crate::error::Result<Vec<u8>> {
    if data.len() > target_len {
        return Err(crate::error::AttestationError::ReportDataTooLarge { max: target_len });
    }
    let mut padded = vec![0u8; target_len];
    padded[..data.len()].copy_from_slice(data);
    Ok(padded)
}

/// SHA-256 hash.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// SHA-384 hash.
pub fn sha384(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Decode URL-safe base64, tolerating optional padding.
pub fn decode_base64url(input: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    BASE64URL.decode(input.trim_end_matches('='))
}

/// Strip trailing null bytes from a byte slice.
/// Returns a subslice without any trailing 0x00 bytes.
pub fn strip_trailing_nulls(data: &[u8]) -> &[u8] {
    let end = data.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &data[..end]
}

/// Compare two byte slices in constant time (best effort).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_report_data_exact() {
        let data = vec![0xAA; 64];
        let padded = pad_report_data(&data, 64).unwrap();
        assert_eq!(padded, data);
    }

    #[test]
    fn test_pad_report_data_short() {
        let data = vec![0xBB; 32];
        let padded = pad_report_data(&data, 64).unwrap();
        assert_eq!(&padded[..32], &data);
        assert_eq!(&padded[32..], &[0u8; 32]);
    }

    #[test]
    fn test_pad_report_data_too_large() {
        let data = vec![0xCC; 65];
        let result = pad_report_data(&data, 64);
        assert!(result.is_err());
    }

    #[test]
    fn test_sha256() {
        let hash = sha256(b"test");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha384() {
        let hash = sha384(b"test");
        assert_eq!(hash.len(), 48);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn test_strip_trailing_nulls() {
        assert_eq!(strip_trailing_nulls(b"hello\0\0\0"), b"hello");
        assert_eq!(strip_trailing_nulls(b"hello"), b"hello");
        assert_eq!(strip_trailing_nulls(b"\0\0\0"), b"" as &[u8]);
        assert_eq!(strip_trailing_nulls(b""), b"" as &[u8]);
        assert_eq!(strip_trailing_nulls(b"a\0b\0\0"), b"a\0b");
    }
}
