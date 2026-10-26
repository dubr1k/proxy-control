#!/usr/bin/python3
"""Fake `mita` for the mieru-manager contract tests (mounted over /usr/bin/mita in a private mount
namespace). State in $FAKE_MITA_DIR: <key>.json config, <key>.running (present = RUNNING),
<key>.metrics.json (`get metrics` output), argv.log. key = "main", or "slot-<hash>" of MITA_UDS_PATH."""
import hashlib
import json
import os
import sys

root = os.environ["FAKE_MITA_DIR"]
uds = os.environ.get("MITA_UDS_PATH")
key = "main" if not uds else "slot-" + hashlib.sha256(uds.encode()).hexdigest()[:16]
config_path = os.path.join(root, key + ".json")
running_path = os.path.join(root, key + ".running")
args = sys.argv[1:]


def write_json(path, value):
    tmp = path + ".tmp.%d" % os.getpid()
    with open(tmp, "w") as out:
        json.dump(value, out)
    os.replace(tmp, path)


with open(os.path.join(root, "argv.log"), "a") as log:
    log.write(json.dumps([key] + ["<fd>" if a.startswith("/proc/") else a for a in args]) + "\n")

if not os.path.exists(config_path):
    if key == "main":
        write_json(config_path, {"portBindings": [{"port": 8443, "protocol": "TCP"}], "loggingLevel": "INFO", "mtu": 1400})
        open(running_path, "w").close()
    else:
        write_json(config_path, {"loggingLevel": "INFO"})

if args == ["version"]:
    print("mita 3.38.1")
elif args == ["help"]:
    print("  apply config <JSON_FILE>\n  replace config <JSON_FILE>\n  describe config")
elif args == ["describe", "config"]:
    with open(config_path) as f:
        print(f.read())
elif len(args) == 3 and args[0] in ("apply", "replace") and args[1] == "config":
    with open(args[2]) as f:
        value = json.load(f)
    for user in value.get("users", []):
        if user.get("password"):
            raw = user["password"]
            user["password"] = ""
            user["hashedPassword"] = hashlib.sha256((raw + "\0" + user["name"]).encode()).hexdigest()
        if user.get("quotas") == []:
            del user["quotas"]
    write_json(config_path, value)
elif args == ["reload"]:
    pass
elif args == ["stop"]:
    if os.path.exists(running_path):
        os.unlink(running_path)
elif args == ["start"]:
    open(running_path, "w").close()
elif args == ["status"]:
    print('mita server status is "%s"' % ("RUNNING" if os.path.exists(running_path) else "IDLE"))
elif args == ["get", "metrics"]:
    metrics = os.path.join(root, key + ".metrics.json")
    if os.path.exists(metrics):
        with open(metrics) as f:
            print(f.read())
    else:
        print('{"users": {}}')
else:
    sys.exit(8)
