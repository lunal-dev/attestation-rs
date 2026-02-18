use crate::types::ProcessorGeneration;

// AMD root certificates bundled at compile time.
// These are the ARK (AMD Root Key) and ASK (AMD SEV Key) for each processor generation.
// They rarely rotate and are safe to embed.

// Milan ARK and ASK
static MILAN_ARK: &[u8] = include_bytes!("../../../certs/amd/milan/ark.der");
static MILAN_ASK: &[u8] = include_bytes!("../../../certs/amd/milan/ask.der");

// Genoa ARK and ASK
static GENOA_ARK: &[u8] = include_bytes!("../../../certs/amd/genoa/ark.der");
static GENOA_ASK: &[u8] = include_bytes!("../../../certs/amd/genoa/ask.der");

// Turin ARK and ASK
static TURIN_ARK: &[u8] = include_bytes!("../../../certs/amd/turin/ark.der");
static TURIN_ASK: &[u8] = include_bytes!("../../../certs/amd/turin/ask.der");

/// Get bundled AMD root certs (ARK, ASK) for a processor generation.
/// Returns (ark_der, ask_der).
pub fn get_bundled_certs(gen: ProcessorGeneration) -> (&'static [u8], &'static [u8]) {
    match gen {
        ProcessorGeneration::Milan => (MILAN_ARK, MILAN_ASK),
        ProcessorGeneration::Genoa => (GENOA_ARK, GENOA_ASK),
        ProcessorGeneration::Turin => (TURIN_ARK, TURIN_ASK),
    }
}

/// Get bundled ARK for a processor generation.
pub fn get_ark(gen: ProcessorGeneration) -> &'static [u8] {
    get_bundled_certs(gen).0
}

/// Get bundled ASK for a processor generation.
pub fn get_ask(gen: ProcessorGeneration) -> &'static [u8] {
    get_bundled_certs(gen).1
}
