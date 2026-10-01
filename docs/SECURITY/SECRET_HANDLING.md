# Never expose a secret

**Standing rule** (owner directive, 2026-09-26; CLAUDE.md rule 9): passwords,
JWTs and other tokens, API keys, private keys and key material, credentialed
DSNs and `.env` values are never shown anywhere. That covers command lines,
echoed commands, logs, error messages, tool or CI output, chat, commits,
URLs and screenshots. It applies to people and AI assistants alike, and to
development secrets as much as production ones.

## How to handle a secret in tooling

- **Pass by name, not by value.** Export it and hand the name to the tool:
  `export PGPASSWORD=...; docker exec -e PGPASSWORD ...`, not
  `-e PGPASSWORD=<value>`. Or use a file (`*_FILE`) or stdin.
- **Read it without printing it.** `VAR=$(grep '^NAME=' .env | cut -d= -f2-)`
  and use `"$VAR"`. Never `cat .env`, `echo "$VAR"`, `env` or `set -x`
  around it.
- **No word-split command strings in zsh.** `X="docker exec -e PGPASSWORD=$P
  ..."; $X` runs a command named after the whole string, and the "command
  not found" error prints it with the secret. Use a shell function:
  `pq(){ docker exec -i -e PGPASSWORD c psql "$@"; }`.
- **Credentialed DSNs** (`postgres://user:pass@...`) go only into a
  variable consumed by the program. They are never echoed, and never logged
  in test output (`t.Log(dsn)`) or error messages.
- **Services** log and return errors without secret values. Redact tokens,
  DSNs and key material, and fingerprint instead of printing.
- **Forwarded user tokens** (6.0.0-beta, `pkg/delegation`): a service
  acting for a user sends the user's bearer token to keycore in
  `X-Vecta-Delegated-Token`, over internal mTLS only. It is a credential:
  never log request headers, never copy it into an audit event, error or
  URL (keycore records who the user is, not the token), and never forward it
  anywhere but keycore. Envoy strips the header from outside requests.
- **Commits:** review `git status` / `git diff --cached` before committing.
  `.env`, keys and binaries never go in.

## If a secret is exposed anyway

1. Say so at once, in plain words. Name the secret, not its value, and say
   where it appeared and whether anything used it.
2. Rotate it: [SECRET_ROTATION.md](SECRET_ROTATION.md). A development secret
   is rotated too.
3. Record the cause in `learning.md`, and fix the tool or habit that leaked
   it.

## Incidents

- **2026-09-26, local `POSTGRES_PASSWORD`:** a zsh command stored in a
  word-split variable failed. Its "command not found" error printed the
  whole command, including the development Postgres password read from
  `.env`, into an AI assistant session's output. Nothing ran against the
  database, and the value was visible only in that session's output.
  Rotation was recommended to the owner (`ALTER USER`, per
  SECRET_ROTATION.md). Cause and fix: see "No word-split command strings in
  zsh" above, and `learning.md` (2026-09-26).
- **2026-10-01, root `admin` password (local deployment):** to run a live
  test, an AI assistant session asked the owner for admin access and
  offered a password file or a token file. The answer came back as the
  password typed into the chat, so it is in that session's transcript. The
  session wrote it to a mode-0600 file, passed it to the login call by file,
  never put it on a command line, and deleted the file and the token after
  the test. Changing the password was recommended to the owner. Cause: the
  question allowed a free-text answer. See `learning.md` (2026-10-01).
