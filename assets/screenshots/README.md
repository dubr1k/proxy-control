# Screenshot policy

Committed captures live next to the release note that uses them (`docs/releases/assets/<version>/`; first set: `v0.3.0-beta.1`, lab data from the `ams-test` install, 2026-09-13). Do not create mock images and present them as product evidence.

Future captures must use an isolated synthetic dataset, RFC example hostnames, synthetic users and nodes, and visibly non-production status. Remove QR codes, proxy/access URLs, tokens, passwords, certificate material, serials/fingerprints, public IPs, production metadata and browser history. Review both pixels and image metadata before commit. Required coverage, once real and sanitized: desktop dashboard, mobile navigation, per-protocol cards, and fleet/degraded-state view.
