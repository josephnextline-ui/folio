// crypto.js — client-side end-to-end encryption helpers
// AES-GCM 256 with a key derived via PBKDF2 (SHA-256, 250k iterations) from
// the shared passphrase + a server-stored salt. Server never sees the key.

const FolioCrypto = (() => {
  const subtle = window.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function b64(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function fromB64(str) {
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function deriveKey(passphrase, saltB64) {
    const baseKey = await subtle.importKey(
      'raw', enc.encode(passphrase),
      { name: 'PBKDF2' }, false, ['deriveKey']
    );
    return subtle.deriveKey(
      { name: 'PBKDF2', salt: fromB64(saltB64), iterations: 250000, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encrypt(key, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      enc.encode(plaintext)
    );
    return { ciphertext: b64(ct), iv: b64(iv) };
  }

  async function decrypt(key, ciphertextB64, ivB64) {
    const pt = await subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(ivB64) },
      key,
      fromB64(ciphertextB64)
    );
    return dec.decode(pt);
  }

  function randomSaltB64() {
    return b64(crypto.getRandomValues(new Uint8Array(16)));
  }

  // Verifier: a known plaintext encrypted with the key — used on subsequent
  // unlocks to confirm the passphrase derives the right key.
  const VERIFIER_PLAINTEXT = 'folio::verifier::v1';

  async function buildVerifier(passphrase) {
    const salt = randomSaltB64();
    const key = await deriveKey(passphrase, salt);
    const check = await encrypt(key, VERIFIER_PLAINTEXT);
    return { salt, check, key };
  }

  async function verifyAndDeriveKey(passphrase, saltB64, check) {
    const key = await deriveKey(passphrase, saltB64);
    try {
      const pt = await decrypt(key, check.ciphertext, check.iv);
      if (pt !== VERIFIER_PLAINTEXT) return null;
      return key;
    } catch (e) {
      return null;
    }
  }

  return { deriveKey, encrypt, decrypt, buildVerifier, verifyAndDeriveKey };
})();
