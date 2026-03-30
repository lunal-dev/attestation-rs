pub mod verify;

#[cfg(all(any(feature = "attest", feature = "attest-gcp-snp"), target_os = "linux"))]
pub mod attest;
