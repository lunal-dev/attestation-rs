fn main() {
    #[cfg(feature = "attestation")]
    {
        use clap::{Arg, Command};
        use lunal_attestation::sev_snp::attest::*;

        let matches = Command::new("attest")
            .version(env!("CARGO_PKG_VERSION"))
            .about("Attestation report tool")
            .arg(
                Arg::new("format")
                    .short('f')
                    .long("format")
                    .value_parser(["raw", "compressed"])
                    .default_value("json")
                    .help("Output format"),
            )
            .arg(
                Arg::new("pretty")
                    .long("pretty")
                    .action(clap::ArgAction::SetTrue)
                    .help("Pretty print JSON"),
            )
            .get_matches();

        let result = match matches.get_one::<String>("format").unwrap().as_str() {
            "raw" => {
                let data: &str = "hello";
                get_attestation_with_data(data).expect("Failed to get raw attestation");
                Ok("test");
            }
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
