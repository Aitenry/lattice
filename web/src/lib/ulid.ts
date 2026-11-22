/**
 * ULID generation (26-char Crockford Base32, matching the backend `lattice_core::ids::new_id`).
 *
 * The frontend uses it for exactly two things: (1) the `Idempotency-Key` of write requests
 * (the API requires a ULID); (2) local temporary row keys. `envelope_id`/`seq` are always
 * assigned by the server (design §17.2) and must never be invented by the client.
 */
const ENC = '0123456789ABCDEFGHJKMNPQRSTVWXYZ' // Crockford: no I L O U

function encodeTime(now: number, len: number): string {
  let out = ''
  let t = now
  for (let i = len - 1; i >= 0; i--) {
    out = ENC[t % 32] + out
    t = Math.floor(t / 32)
  }
  return out
}

function encodeRandom(len: number): string {
  const buf = new Uint8Array(len)
  crypto.getRandomValues(buf)
  let out = ''
  for (let i = 0; i < len; i++) out += ENC[buf[i] % 32]
  return out
}

export function ulid(): string {
  return encodeTime(Date.now(), 10) + encodeRandom(16)
}
