"""Routing (v0.4): an engine-neutral egress policy compiled per backend (ADR 006).

Kept import-free on purpose: the manager clients import the shared vocabulary from
`panel.routing.document` and the protocol adapters build on it, while the service and
routes in this package import those adapters back.
"""
