#!/bin/sh
set -eu

usage() {
    printf 'usage: %s apply|remove PORT MSS\n' "$0" >&2
    exit 2
}

[ "$#" -eq 3 ] || usage
action=$1
port=$2
mss=$3

case "$action" in
    apply|remove) ;;
    *) usage ;;
esac
case "$port" in
    ''|*[!0-9]*) usage ;;
esac
case "$mss" in
    ''|*[!0-9]*) usage ;;
esac
if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    usage
fi
if [ "$mss" -lt 536 ] || [ "$mss" -gt 1460 ]; then
    usage
fi

iptables=${IPTABLES:-/usr/sbin/iptables}
[ -x "$iptables" ] || {
    printf 'iptables executable is unavailable: %s\n' "$iptables" >&2
    exit 1
}

check_rule() {
    "$iptables" -t mangle -C PREROUTING -p tcp --dport "$port" \
        --tcp-flags SYN,RST SYN -m comment \
        --comment proxy-control-mieru-mss-clamp \
        -j TCPMSS --set-mss "$mss" >/dev/null 2>&1
}

if [ "$action" = apply ]; then
    if ! check_rule; then
        "$iptables" -t mangle -I PREROUTING 1 -p tcp --dport "$port" \
            --tcp-flags SYN,RST SYN -m comment \
            --comment proxy-control-mieru-mss-clamp \
            -j TCPMSS --set-mss "$mss"
    fi
    exit 0
fi

while check_rule; do
    "$iptables" -t mangle -D PREROUTING -p tcp --dport "$port" \
        --tcp-flags SYN,RST SYN -m comment \
        --comment proxy-control-mieru-mss-clamp \
        -j TCPMSS --set-mss "$mss"
done
