# Fixed signature fixture

This directory contains a reproducible Ed25519-signed WASM plugin package. The test
`crates/lattice-plugins/src/wasm/tests.rs::real_ed25519_signed_package_registers_as_trusted_and_invokable`
uses these files to verify a real signature, not a mock.

| File | Description |
| --- | --- |
| `plugin.wasm` | A pass-through plugin generated from WAT by `wasm-plugin-fixture wasm echo` |
| `manifest.json` | Namespace `signed-echo`, base64 `signature`, and `signing_key_id=lattice-e2e-fixture-1` |
| `fixture.json` | Verification public key (base64 raw 32 bytes), canonical manifest JSON, and the digest that is signed |

## Signature format

```text
payload   = sha256(wasm_bytes || canonical_manifest_json)   # 32 bytes
signature = ed25519_sign(private_key, payload)               # 64 bytes, base64 in manifest.signature

canonical_manifest_json = {
  "ns": "..",
  "version": "..",
  "entry": "..",
  "deps": [".."],
  "limits": {"memory_mb": 0, "fuel": 0, "timeout_ms": 0}
}
```

The payload is signed over the raw WASM bytes and the canonical manifest JSON, not over the
manifest file as written. The verifier reconstructs the canonical form before checking the
signature.

## Regenerating the fixture

The fixture tools live in the `lattice-plugins` example binary:

```bash
# 1. Generate the WASM module
cargo run -q -p lattice-plugins --example wasm-plugin-fixture -- wasm echo plugin.wasm

# 2. Write manifest.base.json without the signature, using the same fields as
#    fixture.json.canonical_manifest_json

# 3. Produce the canonical JSON and the payload digest
cargo run -q -p lattice-plugins --example wasm-plugin-fixture -- canonical-json manifest.base.json
cargo run -q -p lattice-plugins --example wasm-plugin-fixture -- payload-hash plugin.wasm manifest.base.json
```

For the committed fixture, the Ed25519 private key is derived from a fixed seed:
`sha256("lattice-wasm-plugin-e2e-fixture-v1")`. The seed exists only to make the fixture
reproducible. The derived key is not a production key, and the fixture's public key is the only
entry registered as trusted for this test. Real release keys remain offline with the publisher
and are never stored in the repository.
