fn main() {
    #[cfg(feature = "attestation")]
    {
        use clap::{Arg, Command};
        use lunal_attestation::sev_snp::attest::*;

        let matches = Command::new("attest_sev_snp")
            .version(env!("CARGO_PKG_VERSION"))
            .about("SEV-SNP attestation report tool")
            .arg(
                Arg::new("format")
                    .short('f')
                    .long("format")
                    .value_parser(["raw", "compressed"])
                    .default_value("raw")
                    .help("Output format"),
            )
            .get_matches();

        let result = match matches.get_one::<String>("format").unwrap().as_str() {
            "raw" => {
                let raw =
                    get_raw_attestation_report().expect("Failed to get raw SEV-SNP attestation");
                base64::encode(&raw)
            }
            "compressed" => get_compressed_encoded_attestation()
                .expect("Failed to get compressed SEV-SNP attestation"),
            _ => unreachable!(),
        };

        println!("{}", result);
    }

    #[cfg(not(feature = "attestation"))]
    {
        eprintln!("Error: This binary requires the 'attestation' feature to be enabled.");
        std::process::exit(1);
    }
}
