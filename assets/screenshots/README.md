# Screenshot policy

Committed captures live next to the release note that uses them (`docs/releases/assets/<version>/`, for example `v1.0.0`), taken from an isolated lab install. Do not create mock images and present them as product evidence.

Future captures must use an isolated synthetic dataset, RFC example hostnames, synthetic users and nodes, and visibly non-production status. Remove QR codes, proxy/access URLs, tokens, passwords, certificate material, serials/fingerprints, public IPs, production metadata and browser history. Review both pixels and image metadata before commit. Required coverage, once real and sanitized: desktop dashboard, mobile navigation, per-protocol cards, and fleet/degraded-state view.
