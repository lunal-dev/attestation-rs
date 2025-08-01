import init, { verify_single_attestation } from "./pkg/lunal_attestation.js";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function main() {
  try {
    const wasmPath = join(__dirname, "pkg", "lunal_attestation_bg.wasm");
    const wasmBytes = readFileSync(wasmPath);
    await init(wasmBytes);

    console.log("WASM module initialized successfully");

    const attestation = readFileSync("./attestation.txt", "utf8").trim();
    console.log("Loaded attestation length:", attestation.length);

    console.log("\n=== Testing Detailed DCAP Verification ===");
    try {
      const result = await verify_single_attestation(attestation);
      console.log("Final result:", result);
    } catch (error) {
      console.error("Detailed verification error:", error);
    }
  } catch (error) {
    console.error("Error:", error);
  }
}

main().catch(console.error);
