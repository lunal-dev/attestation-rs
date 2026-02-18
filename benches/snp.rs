use base64::Engine;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use der::Decode;

use attestation::platforms::snp::certs::get_bundled_certs;
use attestation::platforms::snp::claims::extract_claims;
use attestation::platforms::snp::verify::{verify_cert_chain_pub, verify_report_signature_pub, SnpReport};
use attestation::types::ProcessorGeneration;

static SNP_REPORT_BYTES: &[u8] = include_bytes!("../test_data/snp/test-report.bin");
static SNP_VCEK: &[u8] = include_bytes!("../test_data/snp/test-vcek.der");
static IMDS_VCEK: &[u8] = include_bytes!("../test_data/az_snp/imds-vcek.der");
static IMDS_ASK: &[u8] = include_bytes!("../test_data/az_snp/imds-chain-0.der");
static IMDS_ARK: &[u8] = include_bytes!("../test_data/az_snp/imds-chain-1.der");

fn bench_report_parse(c: &mut Criterion) {
    c.bench_function("snp/report_parse", |b| {
        b.iter(|| {
            let report = SnpReport::from_bytes(black_box(SNP_REPORT_BYTES)).unwrap();
            black_box(&report);
        });
    });
}

fn bench_claim_extraction(c: &mut Criterion) {
    let report = SnpReport::from_bytes(SNP_REPORT_BYTES).unwrap();
    c.bench_function("snp/claim_extraction", |b| {
        b.iter(|| {
            let claims = extract_claims(black_box(&report));
            black_box(&claims);
        });
    });
}

fn bench_cert_chain_parse_bundled(c: &mut Criterion) {
    c.bench_function("snp/cert_chain_parse_bundled", |b| {
        b.iter(|| {
            let (ark_der, ask_der) = get_bundled_certs(black_box(ProcessorGeneration::Milan));
            let ark = x509_cert::Certificate::from_der(ark_der).unwrap();
            let ask = x509_cert::Certificate::from_der(ask_der).unwrap();
            black_box((&ark, &ask));
        });
    });
}

fn bench_cert_chain_verify_rsa_pss(c: &mut Criterion) {
    let (ark_der, ask_der) = get_bundled_certs(ProcessorGeneration::Milan);
    c.bench_function("snp/cert_chain_verify_rsa_pss", |b| {
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

fn bench_cert_chain_verify_imds(c: &mut Criterion) {
    c.bench_function("snp/cert_chain_verify_imds", |b| {
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

fn bench_vcek_x509_parse(c: &mut Criterion) {
    c.bench_function("snp/vcek_x509_parse", |b| {
        b.iter(|| {
            let cert = x509_cert::Certificate::from_der(black_box(IMDS_VCEK)).unwrap();
            black_box(&cert);
        });
    });
}

fn bench_evidence_deserialize(c: &mut Criterion) {
    let evidence = attestation::platforms::snp::evidence::SnpEvidence {
        attestation_report: base64::engine::general_purpose::STANDARD
            .encode(SNP_REPORT_BYTES),
        cert_chain: None,
    };
    let json = serde_json::to_string(&evidence).unwrap();

    c.bench_function("snp/evidence_deserialize", |b| {
        b.iter(|| {
            let e: attestation::platforms::snp::evidence::SnpEvidence =
                serde_json::from_str(black_box(&json)).unwrap();
            black_box(&e);
        });
    });
}

fn bench_report_signature_ecdsa(c: &mut Criterion) {
    c.bench_function("snp/report_signature_ecdsa", |b| {
        b.iter(|| {
            let result = verify_report_signature_pub(
                black_box(SNP_REPORT_BYTES),
                black_box(SNP_VCEK),
            )
            .unwrap();
            black_box(&result);
        });
    });
}

criterion_group!(
    benches,
    bench_report_parse,
    bench_claim_extraction,
    bench_cert_chain_parse_bundled,
    bench_cert_chain_verify_rsa_pss,
    bench_cert_chain_verify_imds,
    bench_vcek_x509_parse,
    bench_evidence_deserialize,
    bench_report_signature_ecdsa,
);
criterion_main!(benches);
