<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_Black%20Text%20with%20Color%20Logo.png">
    <img src="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png" width="50%">
  </picture>
</div>

# Automata coco-provider SDK
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Getting Started

By default, this crate enables all its features - `configfs`, `tpm` and `legacy`.

### Features
- `tpm`: This feature must be used for a VM that only exports its attestation report via a TPM module. VMs that support this include Azure Confidential VMs.
- `configfs`: This feature should be the default for most Cloud Service Providers (CSP), such as AWS and GCP.
- `legacy`: This feature should only be enabled on CSPs that support this, and only on AMD SEV-SNP VMs.

> [!NOTE]
> We recommend leaving all features on unless you know which feature to exclude.

### Download Dependencies
When the `tpm` feature is enabled, the following dependencies must be installed:

```bash
sudo apt install pkg-config libtss2-dev
```

### Importing this crate
To use the crate as is, import it into your `Cargo.toml` as follows:

```toml
[dependencies]
coco-provider = { git = "https://github.com/automata-network/coco-provider-sdk" }
```

To use this crate without specific features, eg. `tpm` feature, import it into your `Cargo.toml` as follows:

```toml
[dependencies]
coco-provider = { 
    git = "https://github.com/automata-network/coco-provider-sdk",
    default-features = false,
    features = ["configfs", "legacy"]
}
```

### Using this Crate
This crate exports all the information you need in one function,`get_coco_provider`, which can be used as follows:

```rust
use coco_provider::get_coco_provider;

fn main() {
    let provider = get_coco_provider().unwrap();
    println!("Provider: {:?}", provider);
}

```

## License

The code in [src/coco/snp](./src/coco/snp) is derived from [virtee/sev](https://github.com/virtee/sev/), which is licensed under Apache License 2.0. Some portions have been modified for compatibility and extended functionality.

See [LICENSE](./LICENSE) for full details.
