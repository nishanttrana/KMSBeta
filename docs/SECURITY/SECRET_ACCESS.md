# Secret access rules and version operations

How the secrets service decides who may touch which secret, and what can be
done to a secret's versions. Added in 7.29.0-beta; default-deny, group
subjects, the version cap and retention in 7.30.0-beta. Code:
`services/secrets/access.go` (the decision), `handler.go` (`allowed`,
`secretFor`, `vaultSecret`), `store.go`.

## Two checks, both required

1. **Route permission** (`pkg/route`): what the caller may do with secrets in
   general. `secrets.read`, `secrets.value.read`, `secrets.write`,
   `secrets.delete`, and, granted only by name, `secrets.*` or `*` (not by
   `kms.write`): `secrets.destroy`, `secrets.access.manage`.
   `secrets.access.read` lists rules (`kms.read` grants it).
2. **Access rules**: which callers may do it to the secrets under a path.

## The rule

| Field | Meaning |
|---|---|
| `path` | one secret (`/finance/prod/ledger-db`) or everything under a folder at any depth (`/finance/*`). `*` is allowed only as the last segment. `/*` is every secret |
| `subject_type`, `subject_id` | `user` (token `user_id`), `role` (token `role`), `client` (token `client_id`), `workload` (token workload identity), `group` (the ID of a keycore access group the token's user belongs to). Always derived from the verified token, never from a header or body value |
| `capabilities` | `read` (metadata, versions, history, appearing in lists and counts), `value` (the value, any version), `write` (create, edit, rotate, roll back, restore), `delete` (delete, destroy, destroy a version) |
| `effect` | `allow` or `deny` |

A secret's path is its `path` label (the folder) followed by its name; a
Vault KV path (`app/prod/db`) is already a path. The API returns it as
`path` on every secret.

## The decision (`decide`)

For one capability on one path:

1. A **deny** rule that covers the path, includes the capability and names
   the caller refuses: `403 access_rule_denied`. Deny wins.
2. If any **allow** rule covers the path and includes the capability, only
   callers named by such a rule are allowed. Anyone else:
   `403 not_in_access_rule`.
3. If no allow rule covers the path for that capability, the route permission
   alone decides, unless the tenant is **deny by default**
   (`default_deny`), when it is refused: `403 no_access_rule`.

**Groups.** Membership comes from keycore
(`GET /access/users/{user_id}/groups`, called with the secrets service's
token) and is reused for 30 seconds, so removing someone from a group takes
effect within that time. It is read only when a group rule covers the path.
If it cannot be read, a group rule never allows and a deny group rule is
never skipped: the request is refused with `503 access_groups_unavailable`.

So rules restrict; they never grant what the route permission withholds, and
a tenant with no rules and the default setting behaves as before. Capabilities are independent: a
rule on `value` does not hide metadata.

Every refusal is audited under the route's own action with `result:
refused`, the `reason`, the `path` and the `capability`.

## Where it is enforced

Every route that touches a secret calls the same decision, the Vault KV
routes included (`TestAccessRulesAreEnforcedOnEveryRoute` walks them all):

- A secret the caller may not `read` is left out of `GET /secrets` and of
  `/secrets/stats`. Paging counts visible secrets, so pages stay full.
- Creating or generating a secret needs `write` on the path it will have.
- Renaming or re-labelling a secret needs `write` on the path it moves to as
  well as the one it leaves, so a move is not a way around a rule.
- Service identities are subjects like any other: a restricted path refuses a
  platform service that no rule names. No platform service reads secret
  values today.

## Who can change rules

`secrets.access.manage`. Creating and deleting a rule emit
`audit.secrets.access_rule_created` / `access_rule_deleted` (warning) with
the path, subject, capabilities and effect, and are the Playbooks trigger
`secret_access_rule_changed`. A holder of that permission can always remove
a rule, so a tenant cannot lock itself out. At most 500 rules per tenant.

## Vault settings

`GET /secrets/settings` (`secrets.access.read`), `PUT /secrets/settings`
(`secrets.access.manage`, audited `settings_updated` at warning with the
new and previous values; Playbooks trigger `secret_access_rule_changed`).

| Setting | Effect |
|---|---|
| `default_deny` | a path no allow rule covers is refused for every capability. Uncovered secrets disappear from every caller's lists and counts until a rule covers them; rules can still be managed |
| `max_versions` (0 to 1000, 0: no cap) | when a write adds a version, versions older than the newest `max_versions` are removed in the same transaction. The event carries `versions_pruned`. Lowering the cap prunes at each secret's next write, not at once |
| `deleted_retention_days` (0 to 3650, 0: keep) | a deleted secret is destroyed this many days after its delete. The sweep runs hourly, on the primary only (a member never writes the replicated tables), and emits `audit.secrets.retention_purged` per secret (actor `system:retention`, with `deleted_by`, `deleted_at`, `retention_days`), or the same event with `result: failure` |

## Vault mounts

`/v1/{mount}/data/{path}` addresses the secret named `{path}` when the mount
is `secret` (the root mount) and `{mount}/{path}` otherwise, so two mounts
are two namespaces and the mount is the first segment of the path access
rules match on. `/v1/secret/data/kv/x` and `/v1/kv/data/x` are the same
secret, `kv/x`.

## Versions

| Operation | Route | Notes |
|---|---|---|
| Read a version | `GET /secrets/{id}/value?version=N` | audited `value_read` with `version`; `404 version_not_found` |
| Roll back | `POST /secrets/{id}/rollback` `{version, expected_version?}` | the old value becomes a **new** version under a new data key; nothing is removed. Rolling back to the current version is refused (`409 already_current`) |
| Conditional write | `expected_version` on `PUT /secrets/{id}`, `/rotate`, `/rollback` | refused with `409 version_conflict` if the secret has moved on. Without it, two concurrent writers still cannot both win |
| Delete | `DELETE /secrets/{id}` | recoverable: the secret is marked deleted, its value unreadable (`410 secret_deleted`), its versions kept, its name still taken |
| Restore | `POST /secrets/{id}/restore` | `409 secret_not_deleted` if it is active |
| Destroy | `POST /secrets/{id}/destroy` (`secrets.destroy`) | removes the secret and every version. Playbooks trigger `secret_destroyed` |
| Destroy a version | `DELETE /secrets/{id}/versions/{n}` (`secrets.destroy`) | never the current version (`409 version_is_current`) |

A recoverable delete keeps the material, so an exposure-register entry
(docs/SECURITY/SERVICE_MASTER_KEYS.md) closes on destroy, not on delete.

## Open

- Group membership is cached for 30 seconds per user.
- The version cap is per tenant, not per secret or path.
- A rule's subject is not checked to exist (a role or user ID is free text).
