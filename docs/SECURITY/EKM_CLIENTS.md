# EKM database clients: registration and health

A database client is the Vecta agent on one database host. This document says
how a client is registered, how it proves itself, what its health means, and
what each state on **Enterprise KM → EKM for DBs** stands for. The page itself
shows state and controls only.

Code: `services/ekm/clients.go`, `services/ekm/store_clients.go`,
`services/ekm-agent/enroll.go`. Dashboard:
`web/dashboard/src/components/v3/tabs/ekm/`.

## What the agent does

The agent checks in with the KMS, reports the host's OS metrics and the
database's TDE state (SQL Server and Oracle; `unknown` for other engines), and
nothing else. It holds no key material and performs no key operation. A TDE
key created for a client lives in keycore; wrap and unwrap requests for it are
made by whatever integrates with the database
(`POST /ekm/tde/keys/{id}/wrap`), with an auth-service token and a key access
decision, and are listed under **Key requests**.

So "Healthy" means the agent is reaching the KMS. It does not mean the
database is using a Vecta-held key: the page shows the TDE state the agent
reported and the last key request on record, and claims nothing beyond them.

## Registration

1. **An administrator adds the client** (`POST /ekm/clients`, permission
   `ekm.write`): a name (3 to 40 letters, digits, dots, dashes or
   underscores, unique in the tenant), the database engine and, optionally,
   the host name. The client is **pending**: it has no check-in, no
   credential, and is not counted as connected by any other service. A TDE
   key is created for it in keycore, on the administrator's own authority,
   unless `auto_provision_tde` is `false`.
2. **The administrator issues a registration token**
   (`POST /ekm/clients/{id}/registration-token`). It is 256 random bits,
   returned once, valid for 24 hours and for one use. Only its SHA-256 is
   stored. Issuing another replaces it. Issuing one does not register the
   client.
3. **The agent enrols** (`POST /ekm/clients/enroll`, no auth-service token):
   it presents the token and receives a **client key**, also 256 random bits
   stored only as a SHA-256. The token is cleared in the same statement that
   registers the client, so of two agents presenting one token, one is
   registered and the other refused.
4. **The agent checks in** (`POST /ekm/clients/{id}/check-in`) with the
   client key in the `X-EKM-Client-Key` header, at its heartbeat interval.

On the host:

```bash
# Paste the token, press Enter, then Ctrl-D. It is never typed on a command line.
sudo sh -c 'umask 077; mkdir -p /etc/vecta-ekm; cat > /etc/vecta-ekm/registration-token'
sudo ./ekm-agent -enroll -server https://<kms-host>/svc/ekm -token-file /etc/vecta-ekm/registration-token
sudo ./ekm-agent -service install && sudo ./ekm-agent -service start
```

`-enroll` writes the agent config (mode `0600`, holding the client key),
keeps any database settings already in it, and removes the token file. Add
`-ca <bundle.pem>` when the KMS certificate comes from its internal CA. The
agent refuses a `-server` that is not `https://` and speaks TLS 1.3 only.

**Re-registration.** Issuing a token for a registered client changes nothing
until the token is used; the client key is then replaced and the old one
stops working. This is how a lost or exposed client key is rotated.

## Identity rules

- A client is registered, and is seen, only through a credential the service
  verified: the registration token, the client key, or (for clients from
  before 11.7.0-beta) an auth-service token.
- For a client that is pending or holds a client key, the token-authenticated
  calls (`POST /ekm/agents/register`, `.../heartbeat`, `.../validate-deploy`,
  and their gRPC forms) are refused with `403 client_enrollment_required` or
  `client_key_required`. Those calls accept any token of the tenant, so
  without this any user could register a pending client or keep a dead one
  looking alive.
- The client key travels in its own header, not `Authorization`. A cluster
  member verifies `Authorization` as an auth-service token before forwarding
  a write to the primary and would refuse anything else.
- Verifiers are compared in constant time, and compared even when no such
  client exists.
- **Source IP** is the address the edge proxy saw (`clientip.From`,
  [REQUEST_ORIGIN.md](REQUEST_ORIGIN.md)), never one the caller wrote.

## Health

Health is the age of the last verified check-in, judged by the service
(`clientHealth`). The dashboard holds no threshold of its own.

| State | Meaning |
|---|---|
| Awaiting registration | The client was added; no agent has presented its token |
| Healthy | Last check-in at most 5 minutes ago |
| Degraded | Last check-in more than 5 and at most 60 minutes ago |
| Offline | Last check-in more than 60 minutes ago, or none on record |

The thresholds are fixed and are returned with every response
(`thresholds.healthy_within_sec`, `degraded_within_sec`).

**Check-ins.** Every verified contact is stored (time, source IP, agent
version, the status the agent reported). The newest 120 per client are kept.
The strip on the client's panel shows the last 30, one bar each: a bar is
full height when the check-in came on schedule, shorter and amber when it
came more than 1.6 intervals after the one before, and shortest and red when
more than 4 intervals passed (check-ins were missed). Clicking a bar shows
that check-in; **List** shows all of them as a table.

**Tiles.** Each tile counts the clients in one state and filters the table to
exactly those. A tile takes a colour only while its count needs attention
(awaiting registration, degraded, offline).

## Clients from earlier releases

Rows created by `POST /ekm/agents/register` before 11.7.0-beta are shown as
registered from the time they were created, with credential **Service
token**. They keep checking in through the token-authenticated heartbeat,
which now also records each check-in. Move one to a client key by issuing it
a registration token and running `-enroll` on its host.

## Clustering

`ekm_agents` and `ekm_agent_checkins` are replicated. Enrolment and check-in
are writes, so a member forwards them to the primary.

## Audit

Every call, refused or not, is one event (`pkg/route`). See
[AUDIT_EVENTS_2026-09.md](AUDIT_EVENTS_2026-09.md), "EKM database clients".
No event carries a token or a client key. `audit.ekm.client_enrolled` and
`audit.ekm.client_token_issued` are playbook triggers.

## Still open

- The thresholds are fixed, not per tenant.
- A client going degraded or offline raises no event of its own; the existing
  `audit.ekm.agent_disconnected` is emitted when an agent list or status is
  read after the heartbeat timeout.
- The packaged `heartbeat.sh` / `heartbeat.ps1` scripts
  (`GET /ekm/agents/{id}/deploy`) use an auth-service token, not a client key.
