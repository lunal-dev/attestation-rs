use base64::Engine;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use der::Decode;

use attestation::platforms::snp::certs::get_bundled_certs;
use attestation::platforms::snp::claims::extract_claims as snp_extract_claims;
use attestation::platforms::snp::verify::{verify_cert_chain_pub, SnpReport};
use attestation::platforms::tdx::claims::extract_claims as tdx_extract_claims;
use attestation::platforms::tdx::verify::parse_tdx_quote;
use attestation::types::ProcessorGeneration;

// Pre-load all test data at compile time so benchmarks do zero I/O.
static SNP_REPORT_BYTES: &[u8] = include_bytes!("../test_data/snp/test-report.bin");
static SNP_VCEK: &[u8] = include_bytes!("../test_data/snp/test-vcek.der");
static TDX_QUOTE_V4: &[u8] = include_bytes!("../test_data/tdx_quote_4.dat");
static TDX_QUOTE_V5: &[u8] = include_bytes!("../test_data/tdx_quote_5.dat");
static IMDS_VCEK: &[u8] = include_bytes!("../test_data/az_snp/imds-vcek.der");
static IMDS_ASK: &[u8] = include_bytes!("../test_data/az_snp/imds-chain-0.der");
static IMDS_ARK: &[u8] = include_bytes!("../test_data/az_snp/imds-chain-1.der");

// ---------------------------------------------------------------------------
// SNP benchmarks
// ---------------------------------------------------------------------------

fn bench_snp_report_parsing(c: &mut Criterion) {
    c.bench_function("snp_report_parse", |b| {
        b.iter(|| {
            let report = SnpReport::from_bytes(black_box(SNP_REPORT_BYTES)).unwrap();
            black_box(&report);
        });
    });
}

fn bench_snp_claim_extraction(c: &mut Criterion) {
    // Parse once up-front; the benchmark measures only claim extraction.
    let report = SnpReport::from_bytes(SNP_REPORT_BYTES).unwrap();

    c.bench_function("snp_claim_extraction", |b| {
        b.iter(|| {
            let claims = snp_extract_claims(black_box(&report));
            black_box(&claims);
        });
    });
}

fn bench_snp_cert_chain_parsing(c: &mut Criterion) {
    c.bench_function("snp_cert_chain_parse_bundled", |b| {
        b.iter(|| {
            // Exercise the lookup + x509 DER parse of both certs.
            let (ark_der, ask_der) = get_bundled_certs(black_box(ProcessorGeneration::Milan));
            let ark = x509_cert::Certificate::from_der(ark_der).unwrap();
            let ask = x509_cert::Certificate::from_der(ask_der).unwrap();
            black_box((&ark, &ask));
        });
    });
}

fn bench_snp_cert_chain_verify_rsa_pss(c: &mut Criterion) {
    // Benchmark full RSA-PSS cert chain verification (Milan: ARK -> ASK -> VCEK)
    let (ark_der, ask_der) = get_bundled_certs(ProcessorGeneration::Milan);

    c.bench_function("snp_cert_chain_verify_rsa_pss", |b| {
        b.iter(|| {
            verify_cert_chain_pub(
                black_box(ark_der),
                black_box(ask_der),
                black_box(SNP_VCEK),
            )
            .unwrap();
        });
    });
}

fn bench_snp_cert_chain_verify_imds(c: &mut Criterion) {
    // Benchmark RSA-PSS cert chain verification with real IMDS certs
    c.bench_function("snp_cert_chain_verify_imds", |b| {
        b.iter(|| {
            verify_cert_chain_pub(
                black_box(IMDS_ARK),
                black_box(IMDS_ASK),
                black_box(IMDS_VCEK),
            )
            .unwrap();
        });
    });
}

fn bench_snp_vcek_x509_parse(c: &mut Criterion) {
    c.bench_function("snp_vcek_x509_parse", |b| {
        b.iter(|| {
            let cert = x509_cert::Certificate::from_der(black_box(IMDS_VCEK)).unwrap();
            black_box(&cert);
        });
    });
}

fn bench_snp_evidence_deserialize(c: &mut Criterion) {
    // Benchmark deserialization of a JSON SNP evidence
    let evidence = attestation::platforms::snp::evidence::SnpEvidence {
        attestation_report: base64::engine::general_purpose::STANDARD.encode(SNP_REPORT_BYTES),
        cert_chain: None,
    };
    let json = serde_json::to_string(&evidence).unwrap();

    c.bench_function("snp_evidence_deserialize", |b| {
        b.iter(|| {
            let e: attestation::platforms::snp::evidence::SnpEvidence =
                serde_json::from_str(black_box(&json)).unwrap();
            black_box(&e);
        });
    });
}

// ---------------------------------------------------------------------------
// TDX benchmarks
// ---------------------------------------------------------------------------

fn bench_tdx_v4_quote_parsing(c: &mut Criterion) {
    c.bench_function("tdx_v4_quote_parse", |b| {
        b.iter(|| {
            let quote = parse_tdx_quote(black_box(TDX_QUOTE_V4)).unwrap();
            black_box(&quote);
        });
    });
}

fn bench_tdx_v5_quote_parsing(c: &mut Criterion) {
    c.bench_function("tdx_v5_quote_parse", |b| {
        b.iter(|| {
            let quote = parse_tdx_quote(black_box(TDX_QUOTE_V5)).unwrap();
            black_box(&quote);
        });
    });
}

fn bench_tdx_claim_extraction(c: &mut Criterion) {
    // Parse a v4 quote once; benchmark only claim extraction.
    let quote = parse_tdx_quote(TDX_QUOTE_V4).unwrap();

    c.bench_function("tdx_claim_extraction", |b| {
        b.iter(|| {
            let claims = tdx_extract_claims(black_box(&quote));
            black_box(&claims);
        });
    });
}

fn bench_tdx_evidence_deserialize(c: &mut Criterion) {
    let evidence = attestation::platforms::tdx::evidence::TdxEvidence {
        quote: base64::engine::general_purpose::STANDARD.encode(TDX_QUOTE_V4),
        cc_eventlog: None,
    };
    let json = serde_json::to_string(&evidence).unwrap();

    c.bench_function("tdx_evidence_deserialize", |b| {
        b.iter(|| {
            let e: attestation::platforms::tdx::evidence::TdxEvidence =
                serde_json::from_str(black_box(&json)).unwrap();
            black_box(&e);
        });
    });
}

// ---------------------------------------------------------------------------
// TPM benchmarks
// ---------------------------------------------------------------------------

fn bench_tpm_ak_pub_extraction(c: &mut Criterion) {
    // Build a synthetic TPM2B_PUBLIC for benchmarking
    let mut var_data = Vec::new();
    let mut content = Vec::new();
    content.extend_from_slice(&[0x00, 0x01]); // RSA
    content.extend_from_slice(&[0x00, 0x0B]); // SHA-256
    content.extend_from_slice(&[0x00; 4]); // objectAttributes
    content.extend_from_slice(&[0x00, 0x20]); // authPolicy size=32
    content.extend_from_slice(&[0xAA; 32]); // authPolicy data
    content.extend_from_slice(&[0x00, 0x10]); // symmetric=NULL
    content.extend_from_slice(&[0x00, 0x10]); // scheme=NULL
    content.extend_from_slice(&[0x08, 0x00]); // keyBits=2048
    content.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // exponent=0
    let modulus = vec![0xAB; 256];
    content.extend_from_slice(&(modulus.len() as u16).to_be_bytes());
    content.extend_from_slice(&modulus);
    var_data.extend_from_slice(&(content.len() as u16).to_be_bytes());
    var_data.extend_from_slice(&content);

    c.bench_function("tpm_ak_pub_extraction", |b| {
        b.iter(|| {
            // This exercises the TPM2B_PUBLIC parsing path
            let result = attestation::platforms::tpm_common::verify_tpm_signature(
                &[0u8; 256],
                &[0u8; 100],
                black_box(&var_data),
            );
            // We expect this to fail at signature verification (key is synthetic)
            // but the parsing benchmark is what matters
            black_box(&result);
        });
    });
}

fn bench_tpm_quote_decode(c: &mut Criterion) {
    let quote = attestation::platforms::tpm_common::TpmQuote {
        signature: "ab".repeat(256),
        message: "cd".repeat(200),
        pcrs: (0..24).map(|_| "00".repeat(32)).collect(),
    };

    c.bench_function("tpm_quote_decode", |b| {
        b.iter(|| {
            let result = attestation::platforms::tpm_common::decode_tpm_quote(black_box(&quote)).unwrap();
            black_box(&result);
        });
    });
}

// ---------------------------------------------------------------------------
// Criterion wiring
// ---------------------------------------------------------------------------

criterion_group!(
    snp_benches,
    bench_snp_report_parsing,
    bench_snp_claim_extraction,
    bench_snp_cert_chain_parsing,
    bench_snp_cert_chain_verify_rsa_pss,
    bench_snp_cert_chain_verify_imds,
    bench_snp_vcek_x509_parse,
    bench_snp_evidence_deserialize,
);

criterion_group!(
    tdx_benches,
    bench_tdx_v4_quote_parsing,
    bench_tdx_v5_quote_parsing,
    bench_tdx_claim_extraction,
    bench_tdx_evidence_deserialize,
);

criterion_group!(
    tpm_benches,
    bench_tpm_ak_pub_extraction,
    bench_tpm_quote_decode,
);

criterion_main!(snp_benches, tdx_benches, tpm_benches);
