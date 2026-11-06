# Naive live-meter overlay

`forwardproxy.patch` applies only to klzgrad/forwardproxy commit
`d62c80d3dd2c706b6b87579844d2397bddd18317` (Apache-2.0, upstream
<https://github.com/klzgrad/forwardproxy>). The patch and Go additions are
Apache-2.0. The upstream checkout retains its LICENSE and copyright notices.

The patch meters authenticated CONNECT payload at the forwarding loop, not
network packets or access logs. Counters and the private read-only HTTP endpoint
are process-wide and survive Caddy handler/config reloads. Writes accepted by a
local writer count, including accepted bytes returned together with an error;
this does not claim remote application delivery. Padding headers/tails do not
count. Tunnel lifetime spans both forwarding directions.

Enable the Unix listener with
`PROXY_CONTROL_NAIVE_LIVE_SOCKET=/run/caddy-naive/live.sock`. The service owns its
runtime directory (10003:101, 0750), and the socket is group 101, mode 0660.
Caddy config files remain mode 0400. There is no TCP metrics listener.
`GET /v1/live` returns schema 1 with semantics
`authenticated_connect_payload`, a random process epoch, monotonic elapsed
`sampled_at_ms`, and u64 upload/download/active counters. It exposes no identities
or destinations. Caddy advertises `proxy_control.naive_live_meter`.

Both the fresh-install Dockerfile and the updater's embedded build context use
these exact assets. Update discovery uses the same maintained commit, not the
moving upstream branch HEAD, while Caddy releases and builder digests are discovered
independently. A different upstream commit is refused before building;
updating the pin requires reviewing the new upstream forwarding paths, updating
and testing this patch, and changing both compatibility checks together. Test
with `go test -race $(go list -f '{{join .GoFiles " "}}') live_meter_test.go`
in the patched upstream checkout. Explicit file selection avoids upstream
`TestMain`, which otherwise starts its own server listeners even with `-run`.
