# Audit event names

Every row in `audit_log` carries one of the actions below. The list is the contract:
a name appears here exactly once, and one operator action produces one row whatever
path performed it (the grant lifecycle records the same `grant.*` name for an account on
this panel's own runtime and for one on a linked panel). Rows never carry credentials,
keys or request bodies; `detail_json` holds counts, ids, usernames and codes only.

`panel/tests/test_fleet_v2_post_merge_node.py::test_audit_event_names_are_documented_once`
checks the fleet and grant names against this file.

## Authentication and administrators

| Action | Target | Recorded by |
| --- | --- | --- |
| `auth.login` | username | login |
| `auth.logout` | username | logout |
| `admin.create` | admin id | administrators |
| `admin.update` | admin id | administrators (role, password) |
| `admin.delete` | admin id | administrators |
| `api_key.create` | key id | API keys (the plaintext is never recorded) |
| `api_key.enable` / `api_key.disable` | key id | API keys |
| `api_key.delete` | key id | API keys |

## Runtime users (protocol routes)

| Action | Target | Recorded by |
| --- | --- | --- |
| `user.create`, `user.enable`, `user.disable`, `user.rotate`, `user.delete`, `user.limits`, `user.reset_quota`, `user.access` | MTProxy username | `/api/users*` |
| `naive.create`, `naive.enable`, `naive.disable`, `naive.rotate`, `naive.delete`, `naive.quota`, `naive.traffic.reset`, `naive.access` | NaiveProxy username | `/api/naive/users*` |
| `mieru.create`, `mieru.enable`, `mieru.disable`, `mieru.rotate`, `mieru.delete`, `mieru.quotas`, `mieru.metrics.baseline` | Mieru username | `/api/mieru/users*` |
| `runtime.version.update` | component | version agent (owner from the UI, or a central panel through the node's key) |

## Clients, grants and subscriptions

| Action | Target | Recorded by |
| --- | --- | --- |
| `client.create` | client id | clients |
| `client.active` / `client.suspended` / `client.archived` | client id | client state |
| `client.import` | client id | on-device import of existing users |
| `grant.provision.start` | operation id | provisioning saga |
| `grant.provision.succeeded` / `grant.provision.compensated` / `grant.provision.manual_intervention_required` | operation id | provisioning saga outcome |
| `grant.enable` / `grant.disable` | grant id | the grant lifecycle (local: recorded by the domain façade when the runtime is mirrored; remote: when the desired state is declared) |
| `grant.rotate` | grant id | the grant lifecycle (local: a new active version; remote: a `pending` version the next generation names) |
| `grant.delete` | grant id | the grant lifecycle (local: the account is gone and the row purged; remote: declared `deleted`, purged once the node confirms) |
| `grant.adopt_on_write` | grant id | a protocol route touched a runtime user the panel had not imported yet |
| `grant.credential.capture` | grant id | «Принять доступ» without rotation |
| `grant.credential.adopt` | grant id | «Принять доступ» with rotation (Mieru) |
| `subscription.create` / `subscription.rotate` / `subscription.revoke` | subscription id | subscriptions |

## Nodes (central side)

| Action | Target | Recorded by |
| --- | --- | --- |
| `node.register`, `node.rename`, `node.enable`, `node.disable`, `node.certificates.revoke_all` | node id | Fleet v1 registry (`node.enable`/`node.disable` only for v1 transport) |
| `fleet.node.create`, `fleet.command.queue` | node id | Fleet v1 routes |
| `node.link` | node guid | «Добавить панель» |
| `node.link.update` | node guid | link changes (`changed` lists the fields; a new key is never recorded) |
| `node.pause` / `node.resume` | node guid | pausing a link — also what «disable»/«enable» and `panel.cli node-disable` record for a linked panel |
| `node.import` | node guid | importing the node's users (`accounts`, `without_credential`, `already_linked`) |
| `node.version.update` | node guid | updating a component on a linked panel |
| `node.unlink` | node guid | «Удалить» a linked panel (`node_released`, `node_error` — the class of the node's refusal, `released_imported`; a forced deletion adds `forced` and `abandoned_provisioned`) |

## Routing (v0.4)

| Action | Target | Recorded by |
| --- | --- | --- |
| `routing.policy.update` | policy id | `PUT /api/routing/policies/{node}/{protocol}` (`node_id`, `protocol`, `revision`, `rules`, `default_action`) |
| `routing.policy.apply` | policy id | apply — local: the manager's outcome (`outcome`: `applied` or `failed`, `digest`, `manager_revision`, `readback_sha256`, `replayed` / `error`); linked panel: `outcome: applying` when the generation is published, then the node's report through the pusher |
| `routing.policy.rollback` | policy id | rollback to the manager's previous egress entry (`to_revision` — the policy revision it matches, or null for a hand-written section) |
| `routing.policy.delete` | policy id | `DELETE …` once the node runs «direct, no rules» |

## Nodes (node side, through the central's key)

| Action | Target | Recorded by |
| --- | --- | --- |
| `fleet.generation.accept` | generation | `PUT /api/fleet/v2/generation` (`digest`, `resources`) |
| `fleet.credentials.capture` | panel guid | `POST /api/fleet/v2/credentials/capture` (`purpose`: `escrow` or `import`, the labels answered, unanswered, unsupported and refused — never a value) |
| `fleet.unlink` | panel guid | `POST /api/fleet/v2/unlink` (a central) or `POST /api/nodes/local/unlink` (the owner) |
