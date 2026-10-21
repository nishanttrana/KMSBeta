# Kubernetes KMS v2 plugin

The Vecta KMS plugin encrypts a Kubernetes cluster's Secrets at rest with a
Vecta AES-256 key that never leaves the KMS (13.33.0-beta). It implements
Kubernetes' KMS v2 API (`k8s.io/kms`), runs beside kube-apiserver on every
control-plane node, and calls keycore through the HTTPS edge as an API
client.

## How it works

- kube-apiserver generates its own data encryption key seed and asks the
  plugin to wrap it (`Encrypt`); it unwraps once per seed (`Decrypt`). Every
  Secret is then encrypted locally by kube-apiserver.
- The plugin wraps with AES-GCM under the chosen key in keycore: the wire
  value is `iv(12) || ciphertext || tag`, with AAD binding it to the tenant
  and key. The key_id it reports is `<key id>:v<version>`.
- Rotating the Vecta key changes that key_id, which kube-apiserver notices
  through `Status` and re-wraps with; data wrapped before still decrypts,
  because Decrypt reads the version from the key_id it stored.
- Every wrap and unwrap is a keycore operation: decided by the key's access
  rules and audited by keycore with the API client as the actor.
- `Status` reports unhealthy when the key isn't active, and the plugin
  refuses to start without a working key.
- The socket is created with mode 0600: only root on the node (where
  kube-apiserver runs) can connect. It is local IPC, as Kubernetes requires;
  nothing listens on the network.

## Set up

1. **API client.** Register a REST API client (Administration → User
   Management → clients) with authentication mode API key, approve it, and
   keep its key. Grant it `encrypt` and `decrypt` on the key (Key
   Management → key → Access).
2. **Key.** An active AES-256 key.
3. **Configuration.** Enterprise KM → Kubernetes builds both files from the
   key and client you choose:
   - `/etc/vecta-kms/k8s-kms-plugin.json` (mode 0600): `server`,
     `tenant_id`, `key_id`, `client_id`, `api_key_file`, `ca_file`,
     `socket`, optional `timeout`. Unknown fields are refused.
   - `/etc/vecta-kms/api-key` (mode 0600): the API client's key, alone.
   - `/etc/vecta-kms/ca.pem`: the CA of the KMS edge certificate (PKI tab).
4. **Run the plugin** on each control-plane node: the image
   `services/k8s-kms-plugin/Dockerfile` as a static pod (hostPath
   `/etc/vecta-kms` read-only and `/var/run/vecta-kms`), or the binary as a
   systemd unit. It needs the socket directory and outbound HTTPS to the KMS.
5. **kube-apiserver**: `--encryption-provider-config` pointing at the
   EncryptionConfiguration shown on the page (provider `kms`, `apiVersion:
   v2`, endpoint `unix:///var/run/vecta-kms/kms.sock`), with the socket
   directory mounted into the kube-apiserver pod. Then rewrite existing
   Secrets: `kubectl get secrets --all-namespaces -o json | kubectl replace -f -`.

## Failure behaviour

- The API key is only ever sent to auth's `POST /auth/client-token`, which
  returns a short-lived JWT; a failed exchange fails the call (it is never
  sent elsewhere).
- If keycore can't be reached, `Encrypt`/`Decrypt` fail and kube-apiserver
  serves Secrets it already holds a decrypted seed for; new seeds wait.
- A disabled or destroyed key makes `Status` unhealthy. Destroying the key
  makes the cluster's Secrets unreadable: treat it as destroying them.

## Tested by

`pkg/kmsplugin` tests drive the plugin through k8s.io/kms's own gRPC server
on a Unix socket with the generated KMS v2 client (what kube-apiserver
uses), against a keycore double that answers keycore's shapes and does
AES-GCM per version; keycore's own handler is tested for the same calls
(`TestEncryptWithAADDecryptsByVersionAfterRotation`), and the API-key
exchange against auth's real handler
(`TestAgentAuthExchangesAnAPIKeyWithTheRealHandler`). No live cluster was
used.
