package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"vecta-kms/pkg/ssrfguard"
	"vecta-kms/pkg/svctls"
)

// Credentials for the platform's other external systems (7.38.0-beta,
// owner directive 2026-10-10: every credential for an external service is
// added in one place, Playbooks → Credentials, before a feature can use
// it). They are connections like any other: sealed under the compliance
// master key, never returned, opened only by the one service that uses the
// type (credentialUsers) and audited on every release.
const (
	// categoryCloud: cloud provider accounts for BYOK (the cloud service);
	// an Azure app registration also serves Azure EKM (the ekm service).
	categoryCloud = "cloud"
	// categoryMail: an SMTP relay (governance approval and alert mail).
	categoryMail = "mail"
	// categoryHSM: a PKCS#11 HSM that holds keys (hsm-connector). The HSM
	// that protects the KMS's own keys, its root of trust, is the tenant's
	// profile in the HSM tab and is not a credential here.
	categoryHSM = "hsm"
)

// optionsField carries provider options the form has no field for (a
// non-default API version, a sovereign-cloud token URL), as a JSON object of
// strings. The using service merges it under the named fields.
const optionsField = "options_json"

// credentialTypes are appended to connectionTypes.
var credentialTypes = []ConnectionSpec{
	{Type: "aws", Label: "AWS (access key, optional role)", Category: categoryCloud, Use: "Cloud BYOK",
		Fields: []string{"access_key_id", "secret_access_key"}, Optional: []string{"session_token", "region", "role_arn", "external_id", "endpoint_url", optionsField},
		URLFields: []string{"endpoint_url"}, DefaultEndpoint: "AWS KMS", Secrets: []string{"secret_access_key", "session_token", optionsField}},
	{Type: "azure", Label: "Microsoft Entra app registration (Azure Key Vault)", Category: categoryCloud, Use: "Cloud BYOK, Azure EKM",
		Fields: []string{"tenant_id", "client_id", "client_secret"}, Optional: []string{"vault_url", "vault_name", optionsField},
		URLFields: []string{"vault_url"}, DefaultEndpoint: "login.microsoftonline.com", Secrets: []string{"client_secret", optionsField}},
	{Type: "gcp", Label: "Google Cloud service account", Category: categoryCloud, Use: "Cloud BYOK",
		Fields: []string{"service_account_json"}, Optional: []string{"project_id", "location", "key_ring", optionsField},
		DefaultEndpoint: "cloudkms.googleapis.com", Secrets: []string{"service_account_json", optionsField}},
	{Type: "oci", Label: "Oracle Cloud API signing key", Category: categoryCloud, Use: "Cloud BYOK",
		Fields: []string{"tenancy_ocid", "user_ocid", "fingerprint", "private_key_pem"}, Optional: []string{"private_key_passphrase", "region", "compartment_id", "management_endpoint", optionsField},
		URLFields: []string{"management_endpoint"}, DefaultEndpoint: "Oracle Cloud KMS", Secrets: []string{"private_key_pem", "private_key_passphrase", optionsField}},
	{Type: "alibaba", Label: "Alibaba Cloud access key", Category: categoryCloud, Use: "Cloud BYOK",
		Fields: []string{"access_key_id", "access_key_secret"}, Optional: []string{"region", "endpoint_url", optionsField},
		URLFields: []string{"endpoint_url"}, DefaultEndpoint: "Alibaba Cloud KMS", Secrets: []string{"access_key_secret", optionsField}},
	{Type: "salesforce", Label: "Salesforce connected app", Category: categoryCloud, Use: "Cloud BYOK",
		Fields: []string{"instance_url", "client_id", "client_secret"}, Optional: []string{"username", "password", "security_token", "login_url", optionsField},
		URLField: "instance_url", URLFields: []string{"login_url"}, Secrets: []string{"client_secret", "password", "security_token", optionsField}},
	// A mail relay speaks SMTP, not HTTPS: the host is checked like any
	// outbound address and governance requires TLS before it authenticates.
	{Type: "smtp", Label: "SMTP mail relay", Category: categoryMail, Use: "Governance mail",
		Fields: []string{"host", "port", "from"}, Optional: []string{"username", "password", "ca_pem"},
		HostField: "host", Secrets: []string{"password"}},
	// The library is a path inside the connector's provider workspace (the
	// vendor's PKCS#11 library, uploaded over SSH/SFTP). topology is what
	// the operator says the slot is: a single HSM or the vendor's HA group,
	// which the library presents as one slot.
	{Type: "pkcs11_hsm", Label: "PKCS#11 HSM (keys created in the HSM)", Category: categoryHSM, Use: "Keys, certificate authorities",
		Fields: []string{"library_path", "pin"}, Optional: []string{"slot_id", "token_label", "topology", "vendor"},
		Secrets: []string{"pin"}, Choices: map[string][]string{"topology": {"single", "ha_group"}}},
}

// credentialUseTypes are the connection types each of the new uses may
// open (connectionUsers maps a service identity to its use). A type absent
// from a use's list is refused with connection_use_unsupported.
var credentialUseTypes = map[string][]string{
	"cloud_account": {"aws", "azure", "gcp", "oci", "alibaba", "salesforce", "servicenow"},
	"azure_ekm":     {"azure"},
	"hsm_session":   {"pkcs11_hsm"},
}

// publicFields are returned as a credential's attributes.
var publicFields = map[string][]string{
	"aws":        {"region", "role_arn"},
	"azure":      {"tenant_id", "client_id", "vault_name"},
	"gcp":        {"project_id", "location", "key_ring"},
	"oci":        {"region"},
	"alibaba":    {"region"},
	"smtp":       {"port", "from"},
	"pkcs11_hsm": {"slot_id", "token_label", "topology", "vendor"},
}

// validateCredential checks what the generic field check doesn't: the shape
// of a type's own fields, and every address it names. allow is the tenant's
// approved private networks.
func validateCredential(c Connection, allow ssrfguard.Allow) error {
	spec := connectionByType[c.Type]
	f := func(name string) string { return strings.TrimSpace(c.Fields[name]) }
	if raw := f(optionsField); raw != "" {
		var opts map[string]string
		if json.Unmarshal([]byte(raw), &opts) != nil {
			return errors.New("options_json must be a JSON object of strings")
		}
	}
	for field, choices := range spec.Choices {
		if v := f(field); v != "" && !contains(choices, v) {
			return fmt.Errorf("%s must be one of %s", field, strings.Join(choices, ", "))
		}
	}
	for _, field := range spec.URLFields {
		if v := f(field); v != "" {
			if err := checkOutboundURLAllowing(v, allow); err != nil {
				return fmt.Errorf("%s: %w", field, err)
			}
		}
	}
	switch c.Type {
	case "aws":
		if f("external_id") != "" && f("role_arn") == "" {
			return errors.New("external_id needs a role_arn")
		}
		if arn := f("role_arn"); arn != "" && !reIAMRole.MatchString(arn) {
			return errors.New("role_arn must be an IAM role ARN (arn:aws:iam::123456789012:role/name)")
		}
	case "gcp":
		var sa struct {
			Type       string `json:"type"`
			PrivateKey string `json:"private_key"`
		}
		if json.Unmarshal([]byte(f("service_account_json")), &sa) != nil || sa.Type == "" {
			return errors.New("service_account_json must be the service account key file's JSON")
		}
	case "oci":
		if !strings.Contains(f("private_key_pem"), "PRIVATE KEY") {
			return errors.New("private_key_pem must be the API signing key in PEM")
		}
	case "smtp":
		port, err := strconv.Atoi(f("port"))
		if err != nil || port < 1 || port > 65535 {
			return errors.New("port must be a number between 1 and 65535")
		}
		if (f("username") == "") != (f("password") == "") {
			return errors.New("username and password are set together")
		}
		if !strings.Contains(f("from"), "@") {
			return errors.New("from must be an email address")
		}
		return checkOutboundHost(f("host"), allow)
	case "pkcs11_hsm":
		// The connector confines the library to its provider workspace and
		// is the only process that loads it; here only the shape is checked.
		if lib := f("library_path"); !filepath.IsAbs(lib) || lib != filepath.Clean(lib) {
			return errors.New("library_path must be the absolute path of the PKCS#11 library in the HSM provider workspace")
		}
		if f("slot_id") == "" && f("token_label") == "" {
			return errors.New("slot_id or token_label is required")
		}
		if s := f("slot_id"); s != "" {
			if _, err := strconv.ParseUint(s, 10, 64); err != nil {
				return errors.New("slot_id must be a number")
			}
		}
		if len(c.Fields["pin"]) < 4 {
			return errors.New("pin must be at least 4 characters")
		}
	}
	return nil
}

// checkOutboundHost refuses a non-HTTP endpoint the platform may not reach:
// a platform service, or an address the outbound guard blocks.
func checkOutboundHost(host string, allow ssrfguard.Allow) error {
	if svctls.IsInternalHost(host) {
		return urlError{fmt.Errorf("%s is a platform service, not an external endpoint", host)}
	}
	if err := allow.ValidateHost(host); err != nil {
		return urlError{err}
	}
	return nil
}

// credentialEndpoint is what the list shows for a credential type that has
// no single URL: the mail host, the HSM token or slot, or the provider.
func credentialEndpoint(c Connection) string {
	spec := connectionByType[c.Type]
	switch {
	case spec.HostField != "":
		return strings.TrimSpace(c.Fields[spec.HostField])
	case c.Type == "pkcs11_hsm":
		if l := strings.TrimSpace(c.Fields["token_label"]); l != "" {
			return "token " + l
		}
		return "slot " + strings.TrimSpace(c.Fields["slot_id"])
	}
	for _, field := range spec.URLFields {
		if h := endpointHost(c.Fields[field]); h != "" {
			return h
		}
	}
	return spec.DefaultEndpoint
}

func contains(items []string, v string) bool {
	for _, it := range items {
		if it == v {
			return true
		}
	}
	return false
}
