# Secret access rules and version operations

How the secrets service decides who may touch which secret, and what can be
done to a secret's versions. Added in 7.29.0-beta. Code:
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
| `subject_type`, `subject_id` | `user` (token `user_id`), `role` (token `role`), `client` (token `client_id`), `workload` (token workload identity). Always a field of the verified token, never a header or body value |
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
   alone decides.

So rules restrict; they never grant what the route permission withholds, and
a tenant with no rules behaves as before. Capabilities are independent: a
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

- No default-deny mode: an unlisted path is open to the route permission.
- No groups as subjects; a rule names a user, role, client or workload.
- Deleted secrets are kept until someone destroys them; there is no
  retention period and no cap on versions.
