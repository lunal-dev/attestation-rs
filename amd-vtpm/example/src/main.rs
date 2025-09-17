// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(feature = "attester")]
mod attester_example {
    use amd_vtpm::certs::Vcek;
    use amd_vtpm::hcl::HclReport;
    use amd_vtpm::report::{AttestationReport, Validateable};
    use amd_vtpm::{amd_kds, imds, vtpm};

    use openssl::pkey::PKey;
    use std::error::Error;

    struct Evidence {
        report: Vec<u8>,
        quote: vtpm::Quote,
        certs: imds::Certificates,
    }

    struct Attester;

    impl Attester {
        fn gather_evidence(nonce: &[u8]) -> Result<Evidence, Box<dyn Error>> {
            let report = vtpm::get_report()?;
            let quote = vtpm::get_quote(nonce)?;
            let certs = imds::get_certs()?;

            Ok(Evidence {
                report,
                quote,
                certs,
            })
        }
    }

    struct Verifier;

    impl Verifier {
        fn verify(nonce: &[u8], evidence: &Evidence) -> Result<(), Box<dyn Error>> {
            let Evidence { quote, report, .. } = evidence;

            let hcl_report = HclReport::new(report.clone())?;
            let var_data_hash = hcl_report.var_data_sha256();
            let ak_pub = hcl_report.ak_pub()?;
            let snp_report: AttestationReport = hcl_report.try_into()?;

            let cert_chain = amd_kds::get_cert_chain()?;
            let vcek = Vcek::from_pem(&evidence.certs.vcek)?;

            cert_chain.validate()?;
            vcek.validate(&cert_chain)?;
            snp_report.validate(&vcek)?;

            if var_data_hash != snp_report.report_data[..32] {
                return Err("var_data_hash mismatch".into());
            }
            let der = ak_pub.key.try_to_der()?;
            let pub_key = PKey::public_key_from_der(&der)?;
            quote.verify(&pub_key, nonce)?;

            Ok(())
        }
    }

    #[derive(Default)]
    struct RelyingParty {
        nonce: Vec<u8>,
    }

    impl RelyingParty {
        pub fn request_secret(&mut self) -> Vec<u8> {
            // placeholder for a real nonce, it is usually randomly generated ephemeral value.
            let nonce = "challenge".as_bytes().to_vec();
            self.nonce.clone_from(&nonce);
            nonce
        }

        pub fn release_secret(&self, evidence: &Evidence) -> Result<&'static str, Box<dyn Error>> {
            Verifier::verify(&self.nonce, evidence)?;
            Ok("secret")
        }
    }

    pub fn run() -> Result<(), Box<dyn Error>> {
        let mut rp = RelyingParty::default();
        let nonce = rp.request_secret();

        let evidence = Attester::gather_evidence(&nonce)?;
        let secret = rp.release_secret(&evidence)?;

        println!("Secret: {secret}");
        Ok(())
    }
}

#[cfg(feature = "attester")]
fn main() -> Result<(), std::boxed::Box<dyn std::error::Error>> {
    attester_example::run()
}

#[cfg(not(feature = "attester"))]
fn main() {
    println!("This example requires the 'attester' feature to be enabled.");
}
