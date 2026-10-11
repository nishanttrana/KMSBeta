package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func usageOf(name, body string) []string {
	var out []string
	for _, f := range findMaterial(name, []byte(body)) {
		if f.kind == "crypto_usage" {
			out = append(out, f.algorithm+"@"+itoa(f.line))
		}
	}
	sort.Strings(out)
	return out
}

// Each rule finds what its call, key size or directive names, by the
// catalogue's name; comments and prose don't count.
func TestCryptoUsageRules(t *testing.T) {
	cases := []struct {
		name, body string
		want       []string
	}{
		{"Crypto.java", `Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");
Cipher d = Cipher.getInstance("AES");
Cipher e = Cipher.getInstance("AES/GCM/NoPadding");
MessageDigest md = MessageDigest.getInstance("MD5");
Signature s = Signature.getInstance("SHA1withRSA");
Mac m = Mac.getInstance("HmacSHA256");
SecretKeyFactory f = SecretKeyFactory.getInstance("x"); Cipher p = Cipher.getInstance("PBEWithMD5AndDES");
SSLContext ctx = SSLContext.getInstance("TLSv1.1");
// Cipher.getInstance("RC4") is not used any more
`, []string{"3TDEA@1", "AES-ECB@2", "AES@3", "DES@7", "HMAC-SHA-256@6", "MD5@4", "MD5@7", "SHA-1@5", "TLS-1.1@8"}},
		{"legacy.py", `import hashlib
h = hashlib.md5(data)
g = hashlib.new("sha1")
c = DES3.new(key, DES3.MODE_CBC)
a = AES.new(key, AES.MODE_ECB)
k = rsa.generate_private_key(public_exponent=65537, key_size=1024)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
curve = ec.SECP384R1()
# hashlib.md5 in a comment
`, []string{"AES-ECB@5", "EC-P384@8", "MD5@2", "RSA-1024@6", "SHA-1@3", "TLS-1.0@7", "3TDEA@4"}},
		{"keys.go", `package keys
	sum := md5.Sum(b)
	block, _ := des.NewTripleDESCipher(k)
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	c := elliptic.P256()
	cfg := &tls.Config{MinVersion: tls.VersionTLS10}
	// sha1.New() was replaced
`, []string{"3TDEA@3", "EC-P256@5", "MD5@2", "RSA-1024@4", "TLS-1.0@6"}},
		{"server.ts", `const h = crypto.createHash('sha256');
const c = crypto.createCipheriv('des-ede3-cbc', key, iv);
const e = crypto.createCipheriv("aes-128-ecb", key, null);
const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
`, []string{"3TDEA@2", "AES-128-ECB@3", "RSA-1024@4", "SHA-256@1"}},
		{"Legacy.cs", `var md5 = MD5.Create();
var des = new DESCryptoServiceProvider();
var rsa = new RSACryptoServiceProvider(1024);
aes.Mode = CipherMode.ECB;
var mac = new HMACSHA1(key);
`, []string{"AES-ECB@4", "DES@2", "HMAC-SHA-1@5", "MD5@1", "RSA-1024@3"}},
		{"crypto.c", `EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);
const EVP_MD *md = EVP_md5();
EVP_CIPHER *c = EVP_aes_256_ecb();
RSA_generate_key_ex(rsa, 1024, e, NULL);
`, []string{"3TDEA@1", "AES-256-ECB@3", "MD5@2", "RSA-1024@4"}},
		{"index.php", `$h = md5($password);
$c = openssl_encrypt($data, 'bf-cbc', $key);
$this->md5($x);
`, []string{"Blowfish@2", "MD5@1"}},
		{"nginx.conf", `server {
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers HIGH:!aNULL:!MD5:RC4-SHA:DES-CBC3-SHA;
    # ssl_protocols SSLv3;
}`, []string{"3TDEA@3", "RC4@3", "TLS-1.0@2", "TLS-1.1@2", "TLS-1.2@2"}},
		{"sshd_config", `Ciphers aes256-gcm@openssh.com,3des-cbc
MACs hmac-sha2-256,hmac-md5
KexAlgorithms curve25519-sha256,diffie-hellman-group1-sha1
`, []string{"3TDEA@1", "AES-256-GCM@1", "DH-1024@3", "HMAC-MD5@2", "HMAC-SHA-256@2", "X25519@3"}},
		{"ssl.conf", `SSLProtocol all -SSLv3 -TLSv1 +TLSv1.2
`, []string{"TLS-1.2@1"}},
		{"provision.sh", `openssl genrsa -out key.pem 1024
ssh-keygen -t rsa -b 2048 -f id
`, []string{"RSA-1024@1", "RSA-2048@2"}},
		// Prose, and code that names an algorithm without using it, is not usage.
		{"README.md", "We call hashlib.md5 and Cipher.getInstance(\"DES\") here.\n", nil},
		{"notes.py", "label = 'MD5 is broken'\n", nil},
	}
	for _, c := range cases {
		if got := usageOf(c.name, c.body); !reflect.DeepEqual(got, sortedCopy(c.want)) {
			t.Errorf("%s\n got %q\nwant %q", c.name, got, sortedCopy(c.want))
		}
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// Usage assets are classified by the catalogue, are never "exposed", keep
// no part of the line, and two algorithms on one line are two assets.
func TestCryptoUsageAssets(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	body := `ssl_ciphers RC4-SHA:DES-CBC3-SHA;
ssl_protocols TLSv1.2 TLSv1.3;
`
	assets := svc.materialAssets("t1", "s", "upload", "nginx.conf", findMaterial("nginx.conf", []byte(body)))
	got := map[string]string{}
	ids := map[string]bool{}
	for _, a := range assets {
		got[a.Algorithm] = a.Classification
		ids[a.ID] = true
		if a.AssetType != "crypto_usage" || a.Metadata["api"] != "ssl_ciphers" && a.Metadata["api"] != "ssl_protocols" || assetClass(a) != a.Classification {
			t.Fatalf("asset %+v", a)
		}
		if _, ok := a.Metadata["fingerprint"]; ok {
			t.Fatalf("a usage asset carries a fingerprint: %+v", a.Metadata)
		}
	}
	want := map[string]string{"RC4": "weak", "3TDEA": "weak", "TLS-1.2": "strong", "TLS-1.3": "strong"}
	if !reflect.DeepEqual(got, want) || len(ids) != 4 {
		t.Fatalf("classes %v (%d ids), want %v", got, len(ids), want)
	}
	raw, _ := json.Marshal(assets)
	if strings.Contains(string(raw), "DES-CBC3-SHA") || strings.Contains(string(raw), "RC4-SHA") {
		t.Fatalf("the line reached the asset: %s", raw)
	}
}

// Service tokens, cloud secret keys and a private key inside a JSON key
// file are exposed secrets recorded by fingerprint.
func TestSecretFormats(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p8, _ := x509.MarshalPKCS8PrivateKey(key)
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8}))
	jsonKey, _ := json.Marshal(map[string]string{"type": "service_account", "private_key": pemText, "client_email": "scanner@acme.iam.gserviceaccount.com"})
	// Assembled here so no token-shaped literal is in the repository.
	secrets := map[string]string{
		"github": "gh" + "p_" + strings.Repeat("A1b2", 9),
		"gitlab": "gl" + "pat-" + strings.Repeat("x9", 10),
		"slack":  "xo" + "xb-" + "1234567890-abcdefghij",
		"stripe": "sk" + "_live_" + strings.Repeat("Zq7", 9),
		"google": "AI" + "za" + strings.Repeat("S", 35),
		"aws":    strings.Repeat("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", 1),
		"azure":  strings.Repeat("Q", 86) + "==",
	}
	body := strings.Join([]string{
		"GITHUB_TOKEN=" + secrets["github"],
		"token: " + secrets["gitlab"],
		"SLACK=" + secrets["slack"],
		"STRIPE_KEY=" + secrets["stripe"],
		"maps_key = \"" + secrets["google"] + "\"",
		"aws_secret_access_key = " + secrets["aws"],
		"STORAGE=DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=" + secrets["azure"] + ";EndpointSuffix=core.windows.net",
	}, "\n") + "\n"
	svc, _, _ := newDiscoveryService(t)
	assets := svc.materialAssets("t1", "s", "upload", "settings.env", findMaterial("settings.env", []byte(body)))
	assets = append(assets, svc.materialAssets("t1", "s", "upload", "sa.json", findMaterial("sa.json", jsonKey))...)
	var got []string
	for _, a := range assets {
		got = append(got, a.AssetType+"|"+fmtAny(a.Metadata["provider"])+"|"+a.Algorithm+"|"+a.Classification)
	}
	sort.Strings(got)
	want := []string{
		"api_token|github||exposed", "api_token|gitlab||exposed", "api_token|google||exposed", "api_token|slack||exposed", "api_token|stripe||exposed",
		"cloud_secret_key|aws||exposed", "cloud_secret_key|azure||exposed",
		"private_key_material||RSA-2048|exposed",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("findings\n got %q\nwant %q", got, want)
	}
	raw, _ := json.Marshal(assets)
	for name, s := range secrets {
		if strings.Contains(string(raw), s) {
			t.Fatalf("the %s secret reached the assets", name)
		}
	}
	if strings.Contains(string(raw), "BEGIN") {
		t.Fatal("the private key reached the assets")
	}
}

func fmtAny(v interface{}) string {
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

// A call written over several lines, a name built from pieces, and a name
// held in a variable the same file assigns are found (8.1.0-beta), each on
// the line of its call. Before, a rule saw one line and missed all three.
func TestCryptoUsageAcrossLinesAndVariables(t *testing.T) {
	cases := []struct {
		name, body string
		want       []string
	}{
		{"Multi.java", `class A {
  private static final String ALG = "DES";
  static final int BITS = 1024;
  void f() throws Exception {
    Cipher a = Cipher.getInstance(
        "DESede/CBC/PKCS5Padding");
    Cipher b = Cipher.getInstance("RC4" +
        "/ECB/NoPadding");
    Cipher c = Cipher.getInstance(ALG);
    Cipher d = Cipher.getInstance(Constants.ALG);
    String t = "AES"
        + "/ECB/PKCS5Padding";
    Cipher e = Cipher.getInstance(t);
    MessageDigest m = MessageDigest.getInstance(
        // the legacy digest
        "MD5");
    i++;
    Mac h = Mac.getInstance("HmacSHA1");
  }
}`, []string{"3TDEA@5", "AES-ECB@13", "DES@10", "DES@9", "HMAC-SHA-1@18", "MD5@14", "RC4@7"}},
		{"multi.py", `ALG = "md5"
KEY_SIZE = 1024
class K:
    def __init__(self):
        self.digest = 'sha1'
    def run(self):
        a = hashlib.new(
            ALG)
        b = hashlib.new(self.digest)
        c = rsa.generate_private_key(
            public_exponent=65537,
            key_size=KEY_SIZE,
        )
        d = hashlib.new("sh" "a1")
        e = hashlib.md5(x)  # hashlib.new("md4")
`, []string{"MD5@15", "MD5@7", "RSA-1024@10", "SHA-1@14", "SHA-1@9"}},
		{"multi.go", `package x
const bits = 1024
func f() {
	size := 2048
	k, _ := rsa.GenerateKey(rand.Reader, bits)
	j, _ := rsa.GenerateKey(
		rand.Reader, size)
	h := md5.New()
}`, []string{"MD5@8", "RSA-1024@5", "RSA-2048@6"}},
		{"multi.js", `const algo = 'des-ede3-cbc'
let digest = "md" + "5"
const c = crypto.createCipheriv(
  algo, key, iv)
const h = crypto.createHash(digest)
crypto.generateKeyPairSync('rsa', {
  modulusLength: bits,
})
const bits = 1024
`, []string{"3TDEA@3", "MD5@5", "RSA-1024@7"}},
		{"multi.php", `<?php
$alg = 'des-' . 'ede3-cbc';
$x = openssl_encrypt($data,
    $alg, $key);
$h = hash($this->digest, $data);
`, []string{"3TDEA@3"}},
		{"multi.c", `#define DIGEST_BITS 1024
RSA *r = RSA_generate_key(DIGEST_BITS, 65537, NULL, NULL);
RSA_generate_key_ex(rsa, 2048, e, NULL);
RSA_generate_key_ex(rsa, bits, e, NULL);
`, []string{"RSA-1024@2", "RSA-2048@3"}},
		{"deploy.sh", `openssl genrsa \
  -out server.key \
  1024
ssh-keygen -t rsa -b 2048 -f k
`, []string{"RSA-1024@1", "RSA-2048@4"}},
	}
	for _, c := range cases {
		if got := usageOf(c.name, c.body); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got  %v\n want %v", c.name, got, c.want)
		}
	}

	// A resolved finding names the variable and where it was assigned.
	for _, f := range findMaterial("V.java", []byte("String ALG = \"DES\";\nCipher c = Cipher.getInstance(ALG);\n")) {
		if f.kind == "crypto_usage" && (f.meta["via"] != "ALG" || f.meta["assigned_line"] != 1 || f.line != 2) {
			t.Fatalf("resolved finding: line %d %+v", f.line, f.meta)
		}
	}
}

// What is not a constant is not resolved: a named argument, a name that is
// called, another object's member, a name given many values, and a
// comparison are left alone, so nothing is reported that the file does not
// say.
func TestCryptoUsageDoesNotGuess(t *testing.T) {
	for name, body := range map[string]string{
		"kwarg.py": `f(name="md5")
hashlib.new(name)
`,
		"member.js": `const name = 'md5'
crypto.createHash(user.name)
crypto.createHash(name())
`,
		"compare.java": `if (alg == "DES") { }
Cipher.getInstance(alg);
`,
		"many.py": `a = "md5"
a = "sha1"
a = "md4"
a = "sha256"
a = "sha512"
hashlib.new(a)
`,
		"comment.go": `// bits := 1024
k, _ := rsa.GenerateKey(rand.Reader, bits)
`,
		"string.java": `String s = "Cipher.getInstance(ALG)"; String ALG = "DES";
`,
		"readme.conf": `# ssl_protocols TLSv1 \
note = "x"
`,
	} {
		if got := usageOf(name, body); len(got) != 0 {
			t.Errorf("%s: reported %v", name, got)
		}
	}
	// A statement that never closes stops joining at its limit, and a rule
	// never reaches across it.
	open := "x = foo(\n" + strings.Repeat("  1,\n", maxStatementLines+5) + "h = hashlib.md5(y)\n"
	if got := usageOf("open.py", open); !reflect.DeepEqual(got, []string{"MD5@" + itoa(maxStatementLines+7)}) {
		t.Errorf("unclosed statement: %v", got)
	}
}
