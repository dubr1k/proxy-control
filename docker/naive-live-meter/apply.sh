#!/bin/sh
set -eu
# Bounded compatibility contract: a changed upstream needs a reviewed new patch.
expected=d62c80d3dd2c706b6b87579844d2397bddd18317
[ "$1" = "$expected" ] || { echo 'unsupported forwardproxy commit for Naive live-meter schema 1' >&2; exit 1; }
git init /src/forwardproxy
git -C /src/forwardproxy fetch --depth=1 https://github.com/klzgrad/forwardproxy.git "$expected"
git -C /src/forwardproxy checkout --detach FETCH_HEAD
[ "$(git -C /src/forwardproxy rev-parse HEAD)" = "$expected" ]
git -C /src/forwardproxy apply --check /live-meter/forwardproxy.patch
git -C /src/forwardproxy apply /live-meter/forwardproxy.patch
cp /live-meter/live_meter.go /live-meter/live_meter_test.go /src/forwardproxy/
