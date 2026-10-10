package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	neturl "net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// How a bucket's connection authenticates (7.39.0-beta). Besides a static
// S3 access key and an Azure SAS token:
//
//   - s3 with role_arn: the key signs one AssumeRole call to AWS STS, and
//     the scan reads with the temporary credentials it returns. The stored
//     key then needs no access to the bucket itself.
//   - azure_blob with account_key: every request is signed with the storage
//     account's Shared Key (HMAC-SHA256). The key grants the whole account,
//     which is why a SAS token or Entra ID is the better choice.
//   - azure_blob with azure_tenant_id, client_id and client_secret: an Entra
//     ID application's token (client credentials) for Azure Storage.
//   - gcs: a Google service account key signs a short-lived assertion
//     (RS256) that Google exchanges for a read-only access token.
//
// A secret is sent only where it belongs: the Entra client secret to the
// Entra token endpoint, the Google assertion to Google's token endpoint. AWS
// keys and the Azure account key are never sent, only signatures made with
// them. Tokens and temporary credentials live for one scan, in memory.

const (
	entraLogin     = "https://login.microsoftonline.com"
	googleTokenURL = "https://oauth2.googleapis.com/token"
	awsSTSURL      = "https://sts.%s.amazonaws.com/"
	storageScope   = "https://storage.azure.com/.default"
	gcsReadScope   = "https://www.googleapis.com/auth/devstorage.read_only"
)

var (
	reRoleARN     = regexp.MustCompile(`^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]{1,512}$`)
	reAzureTenant = regexp.MustCompile(`^[A-Za-z0-9.-]{1,128}$`)
	reAccountName = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
)

// bucketCredential is an opened connection, held for one scan.
type bucketCredential struct {
	// s3
	accessKey, secretKey, sessionToken string
	roleARN, externalID                string
	// azure
	sas                                 neturl.Values
	accountName                         string
	accountKey                          []byte
	entraTenant, clientID, clientSecret string
	// gcs
	serviceAccount *googleServiceAccount
	// bearer is the access token obtained for this scan (Entra or Google).
	bearer string
}

type googleServiceAccount struct {
	Type        string `json:"type"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	KeyID       string `json:"private_key_id"`
}

// bucketCredential opens the bucket's connection. It must be of the
// provider's type and for the bucket's own host: a credential is never used
// against a host its connection doesn't name. It makes no request.
func (s *Service) bucketCredential(ctx context.Context, b Bucket) (bucketCredential, error) {
	if b.ConnectionID == "" {
		return bucketCredential{}, nil
	}
	if s.conns == nil {
		return bucketCredential{}, errConnectionsUnset
	}
	conn, err := s.conns.Resolve(ctx, b.TenantID, b.ConnectionID)
	if err != nil {
		return bucketCredential{}, fmt.Errorf("connection %s: %w", b.ConnectionID, err)
	}
	unfit := func(msg string) (bucketCredential, error) {
		return bucketCredential{}, fmt.Errorf("%w: %s", errConnectionUnfit, msg)
	}
	if want := bucketProviders[b.Provider]; conn.Type != want {
		return unfit(fmt.Sprintf("%s is a %s connection, not %s", b.ConnectionID, conn.Type, want))
	}
	if !strings.EqualFold(conn.Endpoint, b.host()) {
		return unfit(fmt.Sprintf("its credential is for %s, not %s", conn.Endpoint, b.host()))
	}
	f := func(k string) string { return strings.TrimSpace(conn.Fields[k]) }
	switch b.Provider {
	case "azure":
		switch {
		case f("sas_token") != "":
			sas, err := neturl.ParseQuery(strings.TrimPrefix(f("sas_token"), "?"))
			if err != nil || sas.Get("sig") == "" {
				return unfit("its SAS token is not a signed query string")
			}
			return bucketCredential{sas: sas}, nil
		case f("account_key") != "":
			key, err := base64.StdEncoding.DecodeString(f("account_key"))
			// An HMAC key under 112 bits is not approved, and panics in FIPS-only mode.
			if err != nil || len(key) < 14 {
				return unfit("its account key is not a base64 storage account key")
			}
			// account.blob.core.windows.net names the account; an address
			// does not.
			name := f("account_name")
			if _, err := netip.ParseAddr(b.host()); name == "" && err != nil {
				name, _, _ = strings.Cut(b.host(), ".")
			}
			if !reAccountName.MatchString(name) {
				return unfit("its storage account name can't be read from the address; set account_name")
			}
			return bucketCredential{accountName: name, accountKey: key}, nil
		case f("client_secret") != "":
			if !reAzureTenant.MatchString(f("azure_tenant_id")) || f("client_id") == "" {
				return unfit("its Entra ID application needs azure_tenant_id, client_id and client_secret")
			}
			return bucketCredential{entraTenant: f("azure_tenant_id"), clientID: f("client_id"), clientSecret: f("client_secret")}, nil
		}
		return unfit("it holds no SAS token, account key or Entra ID application")
	case "gcs":
		var sa googleServiceAccount
		if json.Unmarshal([]byte(conn.Fields["service_account_json"]), &sa) != nil || sa.Type != "service_account" || sa.ClientEmail == "" || !strings.Contains(sa.PrivateKey, "PRIVATE KEY") {
			return unfit("its service_account_json is not a Google service account key file")
		}
		return bucketCredential{serviceAccount: &sa}, nil
	}
	cred := bucketCredential{accessKey: f("access_key_id"), secretKey: f("secret_access_key"), roleARN: f("role_arn"), externalID: f("external_id")}
	// An HMAC key under 112 bits is not approved, and panics in FIPS-only mode.
	if cred.accessKey == "" || len("AWS4"+cred.secretKey) < 14 {
		return unfit("its access key is missing or its secret key is too short to sign with")
	}
	if cred.roleARN != "" && !reRoleARN.MatchString(cred.roleARN) {
		return unfit("its role_arn is not an IAM role ARN")
	}
	return cred, nil
}

// authorize obtains what a credential needs before its first request:
// temporary credentials for an assumed role, or an access token.
func (s *Service) authorize(ctx context.Context, client *http.Client, b Bucket, cred *bucketCredential) error {
	switch {
	case cred.roleARN != "":
		return s.assumeRole(ctx, client, b, cred)
	case cred.clientSecret != "":
		form := neturl.Values{"grant_type": {"client_credentials"}, "client_id": {cred.clientID}, "client_secret": {cred.clientSecret}, "scope": {storageScope}}
		token, err := s.fetchToken(ctx, client, s.entraURL+"/"+neturl.PathEscape(cred.entraTenant)+"/oauth2/v2.0/token", form, "Entra ID")
		cred.bearer = token
		return err
	case cred.serviceAccount != nil:
		assertion, err := googleAssertion(cred.serviceAccount, s.googleURL, s.now())
		if err != nil {
			return err
		}
		form := neturl.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
		token, err := s.fetchToken(ctx, client, s.googleURL, form, "Google")
		cred.bearer = token
		return err
	}
	return nil
}

// fetchToken posts form to an OAuth token endpoint and returns the access
// token. Of a refusal it reports only the endpoint's error code.
func (s *Service) fetchToken(ctx context.Context, client *http.Client, tokenURL string, form neturl.Values, who string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%s token request could not be built", who)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "VectaKMS-Discovery")
	resp, err := client.Do(req)
	if err != nil {
		var ue *neturl.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return "", fmt.Errorf("%s token endpoint unreachable: %v", who, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		code := ""
		if reErrorCode.MatchString(strings.ReplaceAll(out.Error, "_", "")) {
			code = " (" + out.Error + ")"
		}
		return "", fmt.Errorf("%s refused the connection's credential%s: HTTP %d", who, code, resp.StatusCode)
	}
	return out.AccessToken, nil
}

// googleAssertion is the signed JWT a service account exchanges for a
// read-only storage token (RS256, valid ten minutes).
func googleAssertion(sa *googleServiceAccount, audience string, now time.Time) (string, error) {
	enc := func(v interface{}) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	if sa.KeyID != "" {
		header["kid"] = sa.KeyID
	}
	input := enc(header) + "." + enc(map[string]interface{}{
		"iss": sa.ClientEmail, "scope": gcsReadScope, "aud": audience, "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	})
	sig, err := pkgcrypto.SignPKCS1v15SHA256PEM(sa.PrivateKey, []byte(input))
	if err != nil {
		return "", fmt.Errorf("%w: its service account private key can't sign: %v", errConnectionUnfit, err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// assumeRole asks AWS STS for temporary credentials for the connection's
// role, signed with its access key, and replaces the key with them.
func (s *Service) assumeRole(ctx context.Context, client *http.Client, b Bucket, cred *bucketCredential) error {
	q := neturl.Values{"Action": {"AssumeRole"}, "Version": {"2011-06-15"}, "RoleArn": {cred.roleARN}, "RoleSessionName": {"vecta-kms-discovery"}, "DurationSeconds": {"900"}}
	if cred.externalID != "" {
		q.Set("ExternalId", cred.externalID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(s.stsURL, b.Region)+"?"+canonicalQuery(q), nil)
	if err != nil {
		return errors.New("the role request could not be built")
	}
	req.Header.Set("User-Agent", "VectaKMS-Discovery")
	signV4(req, *cred, b.Region, "sts", s.now())
	resp, err := client.Do(req)
	if err != nil {
		var ue *neturl.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("AWS STS unreachable: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("AWS STS refused to assume the role%s: HTTP %d", errorCode(resp), resp.StatusCode)
	}
	var out struct {
		AccessKeyID string `xml:"AssumeRoleResult>Credentials>AccessKeyId"`
		Secret      string `xml:"AssumeRoleResult>Credentials>SecretAccessKey"`
		Token       string `xml:"AssumeRoleResult>Credentials>SessionToken"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil || out.AccessKeyID == "" || out.Token == "" || len("AWS4"+out.Secret) < 14 {
		return errors.New("AWS STS did not return temporary credentials")
	}
	cred.accessKey, cred.secretKey, cred.sessionToken, cred.roleARN = out.AccessKeyID, out.Secret, out.Token, ""
	return nil
}

// errorCode reads a storage or token service's error code out of its
// answer, as " (Code)", and nothing else: XML <Code> (S3, Azure, STS) or a
// JSON reason (Google).
func errorCode(resp *http.Response) string {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var x struct {
		Code   string `xml:"Code"`
		Nested string `xml:"Error>Code"`
	}
	_ = xml.Unmarshal(raw, &x)
	var j struct {
		Error struct {
			Status string `json:"status"`
			Errors []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &j)
	for _, c := range []string{x.Code, x.Nested, firstReason(j.Error.Errors), j.Error.Status} {
		if c = strings.ReplaceAll(c, "_", ""); reErrorCode.MatchString(c) {
			return " (" + c + ")"
		}
	}
	return ""
}

func firstReason(errs []struct {
	Reason string `json:"reason"`
}) string {
	if len(errs) > 0 {
		return errs[0].Reason
	}
	return ""
}

// signV4 signs a bodyless GET with AWS Signature Version 4 for service
// ("s3", "sts"). The request's path and query must already be in canonical
// encoding. Temporary credentials add their session token as a signed
// header.
func signV4(req *http.Request, cred bucketCredential, region, service string, now time.Time) {
	stamp := now.UTC().Format("20060102T150405Z")
	date := stamp[:8]
	req.Header.Set("X-Amz-Date", stamp)
	req.Header.Set("X-Amz-Content-Sha256", emptySHA256)
	signed := "host;x-amz-content-sha256;x-amz-date"
	headers := "host:" + req.URL.Host + "\nx-amz-content-sha256:" + emptySHA256 + "\nx-amz-date:" + stamp + "\n"
	if cred.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", cred.sessionToken)
		signed += ";x-amz-security-token"
		headers += "x-amz-security-token:" + cred.sessionToken + "\n"
	}
	canonical := strings.Join([]string{req.Method, req.URL.EscapedPath(), req.URL.RawQuery, headers, signed, emptySHA256}, "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hex.EncodeToString(pkgcrypto.SHA256([]byte(canonical)))
	key := []byte("AWS4" + cred.secretKey)
	for _, part := range []string{date, region, service, "aws4_request"} {
		key = pkgcrypto.HMACSHA256(key, []byte(part))
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+cred.accessKey+"/"+scope+", SignedHeaders="+signed+", Signature="+hex.EncodeToString(pkgcrypto.HMACSHA256(key, []byte(toSign))))
}

// signSharedKey signs a bodyless GET with an Azure storage account's Shared
// Key. x-ms-version must already be set.
func signSharedKey(req *http.Request, cred bucketCredential, now time.Time) {
	date := now.UTC().Format(http.TimeFormat)
	req.Header.Set("x-ms-date", date)
	resource := "/" + cred.accountName + req.URL.EscapedPath()
	q := req.URL.Query()
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		resource += "\n" + strings.ToLower(k) + ":" + strings.Join(vals, ",")
	}
	// GET, then eleven header slots of which only Range can be set, then
	// the x-ms headers and the resource.
	toSign := "GET" + strings.Repeat("\n", 11) + req.Header.Get("Range") + "\n" +
		"x-ms-date:" + date + "\nx-ms-version:" + req.Header.Get("x-ms-version") + "\n" + resource
	req.Header.Set("Authorization", "SharedKey "+cred.accountName+":"+base64.StdEncoding.EncodeToString(pkgcrypto.HMACSHA256(cred.accountKey, []byte(toSign))))
}
