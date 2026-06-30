# Security & fidelity review — findings and fixes

The client was put through an adversarial multi-agent review against both
`docs/PROTOCOL.md` and the original H3C binary. Each verified finding below was
fixed and is covered by a regression test where practical.

## Critical protocol decision (resolved during RE)

* **Login password is cleartext-in-TLS, not RSA/AES.** The SSL VPN library links
  no asymmetric primitive (`RSA_public_encrypt`/`EVP_PKEY_encrypt`/`SM2_encrypt`
  are not imported); `buildSslAuthPacketV7` only URL-encodes. The `szUserRsaKey`
  symbols are unreachable/other-module. See `PROTOCOL.md` Addendum A. An optional
  `--rsa-pubkey` mode remains for firmware variants.

## Fixed findings

| Sev | Area | Issue | Fix |
|---|---|---|---|
| HIGH | `httpclient.py` | Unbounded reads (header / `Content-Length` / chunked) → memory-exhaustion DoS from a hostile gateway | Hard caps: 64 KiB header, 16 MiB body, 100k chunk limit → `HTTPError` |
| HIGH | `httpclient.py` | Chunked `0`-chunk **trailer** not drained → keep-alive desync corrupting the next response / tunnel bytes | Drain trailer lines until the terminating blank line |
| HIGH | `vnic.py` | `EXCLUDE ROUTES` parsed but never programmed; in full-tunnel the gateway IP wasn't carved out → tunnel could route into itself | Bypass routes via the original default gateway; always exclude the gateway IP in full-tunnel |
| MED | `tunnel.py` | Heartbeat sent every 1 s instead of every `KEEPALIVETIME` s (binary divisor `+0x40`) | Send interval driven by `KEEPALIVETIME` from the param block |
| MED | `tunnel.py` | `wait_netconfig` dropped early `type=1` data frames | Early frames retained in `_early` and replayed by `run()` |
| MED | `vnic.py` | `resolv.conf` restore lived only in memory → permanent DNS hijack on crash; a 2nd run could capture its own file | On-disk backup + marker detection + atomic (`tmp`+`os.replace`) write |
| MED | `vnic.py` | Added IPv6 routes not tracked → stale routes after disconnect; no IPv6 full-tunnel default | Track routes by family for cleanup; install IPv6 split-default |
| MED | `session.py` | `NET_EXTEND` response assumed raw frames; a real gateway may send an HTTP preamble / param block in the body | `_read_tunnel_preamble` strips an optional `HTTP/1.x` preamble and parses a body param block |
| LOW | `transport.py` | SECLEVEL not lowered on the fingerprint-pin path → handshake could fail with old gateways, making the *secure* path less usable than `--insecure` | Lower SECLEVEL when pinning OR not verifying (trust is independent of X.509 policy) |
| LOW | `protocol.py` | `is_challenge` could be true on a `Success` response carrying a stray `<type>` → spurious 2FA loop | `is_challenge` returns false when `is_success` |
| LOW | `session.py` | `version` detection was a no-op (always V7) | Detect V7 vs V3 from `Server:` and warn on V3 |
| LOW | `session.py` | EAD host-check POST missing `Referer` (spec §3.7) | Send the `Referer` header |
| LOW | `vnic.py` | `ifreq` packed as 18 bytes; relied on a CPython quirk | Zero-pad to the full 40-byte `struct ifreq` |
| LOW | `crypto.py`/`spa.py` | SPA HOTP digit count (5 vs 6 was unresolved) | `digits=5` + RFC 4226 Luhn checksum = exactly 6 bytes (matches `addChecksum=1`) |

## Notes

* The review's automated verify stage hit a provider session limit mid-run; the
  stage-1 findings were recovered from the run transcripts and each was
  re-verified by hand against the code/spec/binary before fixing.
* Remaining "validate against a live gateway" items are tracked in
  `docs/INTEROP.md` (the `<private>` blob bytes, param-block on-wire framing,
  exact `macAddress`/`language` formatting).
