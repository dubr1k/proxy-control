"""Turn a client config (the file the panel hands out) into the UAPI body of a client amneziawg-go.

  python scripts/lab/awg_conf_to_uapi.py <repo> <conf> <endpoint host:port>
Prints the body; the endpoint of the config is replaced because the lab reaches the server over a veth.
"""
from __future__ import annotations

import sys

repo, conf, endpoint = sys.argv[1:4]
sys.path.insert(0, repo)
from awg_manager import keys, obfuscation  # noqa: E402

section, interface, peer = None, {}, {}
for raw in open(conf, encoding="utf-8").read().splitlines():
    line = raw.strip()
    if not line:
        continue
    if line.startswith("["):
        section = line.strip("[]")
        continue
    name, _, value = line.partition("=")
    (interface if section == "Interface" else peer)[name.strip()] = value.strip()
OBFUSCATION = {"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5",
               "HeaderProtectionKey", "ContentPaddingAddition"}
obf = {k: v for k, v in interface.items() if k in OBFUSCATION}
lines = [f"private_key={keys.hexkey(interface['PrivateKey'])}", *obfuscation.uapi_lines(obf),
         f"public_key={keys.hexkey(peer['PublicKey'])}", f"preshared_key={keys.hexkey(peer['PresharedKey'])}",
         f"endpoint={endpoint}", "replace_allowed_ips=true", "allowed_ip=0.0.0.0/0", "persistent_keepalive_interval=5"]
sys.stdout.write("\n".join(lines) + "\n")
sys.stderr.write(f"address={interface['Address']} mtu={interface.get('MTU', '1280')}\n")
