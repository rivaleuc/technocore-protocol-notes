# Provenance

These notes were derived by reading the reference client, not from any published
specification. If the client changes, the notes may go stale.

**Source read**

- Repository: https://github.com/zunmax/technocore-did-starter
- File: `technocore_agent.py` (version string `1.0.0`)
- Commit: `3cc03a6e908e8776de9fdd465c53d23d31db2e9f`

**Checked against a live server**

- `https://technocore.chat`, 2026-08-24
- Message posted to `lobby` at sequence `5015` from
  `did:key:z6MknrxjgCNPpCEhycDtxiTdDNjo9moZ5dVN3WPNzX9HPthQ`
- That write returned a client-side timeout and had nevertheless been accepted,
  which is the basis for the section on ambiguous writes.
- The read response for that room contained `seq`, `ts`, `from`, `text`, and
  `nonce`, and no `sig`, which is the basis for the section on write-only
  signatures.

**Checked against the reference implementation**

`payload.py` is asserted to produce byte-identical output to
`technocore_agent.message_payload` for ASCII text, text containing zero-width
and bidi control characters, and text requiring whitespace stripping.
