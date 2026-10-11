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

// A function with no arguments that only returns a literal, a format call
// and an interpolated string are read as the literal they produce
// (9.2.0-beta).
func TestCryptoUsageThroughFunctionsAndFormats(t *testing.T) {
	cases := []struct {
		name, body string
		want       []string
	}{
		{"Fn.java", `class A {
  private String algorithm() {
    return "DES";
  }
  static int bits() { return 1024; }
  String mode() { return pick(); }
  void f() throws Exception {
    Cipher a = Cipher.getInstance(algorithm());
    Cipher b = Cipher.getInstance(this.algorithm());
    Cipher c = Cipher.getInstance(String.format("%s/%s/PKCS5Padding", "RC4", "ECB"));
    Cipher d = Cipher.getInstance(String.format("%s/CBC/PKCS5Padding", ALG));
    Cipher e = Cipher.getInstance(mode());
    Cipher g = Cipher.getInstance(other.algorithm());
  }
  static final String ALG = "DESede";
}`, []string{"3TDEA@11", "DES@8", "DES@9", "RC4@10"}},
		{"fn.py", `PREFIX = "sha"
def digest():
    return "md5"
def other(x):
    return "md4"
class K:
    def name(self):
        return 'sha1'
    def run(self):
        a = hashlib.new(digest())
        b = hashlib.new(self.name())
        c = hashlib.new(f"{PREFIX}1")
        d = hashlib.new("{}{}".format("md", 4))
        e = hashlib.new("%s5" % "md")
        f = hashlib.new(other(1))
        g = hashlib.new("%s-%s" % ("x",))
`, []string{"MD4@13", "MD5@10", "MD5@14", "SHA-1@11", "SHA-1@12"}},
		{"fn.go", `package x
const family = "RSA"
func keyBits() int {
	return 1024
}
func curve() string { return "P256" }
func f() {
	k, _ := rsa.GenerateKey(rand.Reader, keyBits())
	_ = k
}`, []string{"RSA-1024@8"}},
		{"fn.js", `const algo = () => 'des-ede3-cbc'
const name = "md"
function digest() {
  return "sha1"
}
const c = crypto.createCipheriv(algo(), key, iv)
const h = crypto.createHash(digest())
const g = crypto.createHash(` + "`${name}5`" + `)
const i = crypto.createHash(` + "`${unknown}5`" + `)
`, []string{"3TDEA@6", "MD5@8", "SHA-1@7"}},
		{"fn.kt", `val family = "DES"
fun algorithm() = "RC4"
val a = Cipher.getInstance("$family/CBC/PKCS5Padding")
val b = Cipher.getInstance("${family}ede/CBC/PKCS5Padding")
val c = Cipher.getInstance(algorithm())
`, []string{"3TDEA@4", "DES@3", "RC4@5"}},
		{"fn.rb", `def digest
  'md5'
end
NAME = "des"
c = OpenSSL::Cipher.new("#{NAME}-cbc")
`, []string{"DES@5"}},
		{"fn.php", `<?php
$alg = 'des';
$x = openssl_encrypt($data, "{$alg}-cbc", $key);
$y = openssl_encrypt($data, sprintf("%s-ede3-cbc", "des"), $key);
`, []string{"3TDEA@4", "DES@3"}},
	}
	for _, c := range cases {
		if got := usageOf(c.name, c.body); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got  %v\n want %v", c.name, got, c.want)
		}
	}
}

// A constant one file defines names the algorithm in a call in another
// file of the same scan (9.2.0-beta): the files of an archive, of a
// repository, of the workspace. Only names written as constants cross
// files, the finding says where the constant is defined, and nothing is
// reported twice.
func TestCryptoUsageAcrossFiles(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	files := map[string]string{
		"src/Constants.java": "public final class Constants {\n  public static final String CIPHER = \"DES/CBC/PKCS5Padding\";\n  public static final int KEY_BITS = 1024;\n  static String local = \"RC4\";\n}\n",
		"src/Use.java":       "class Use {\n  void f() throws Exception {\n    Cipher a = Cipher.getInstance(Constants.CIPHER);\n    Cipher b = Cipher.getInstance(CIPHER);\n    Cipher c = Cipher.getInstance(local);\n    MessageDigest m = MessageDigest.getInstance(\"MD5\");\n  }\n}\n",
		"lib/settings.py":    "DIGEST = 'sha1'\n",
		"lib/hasher.py":      "from settings import DIGEST\nh = hashlib.new(DIGEST)\nk = rsa.generate_private_key(public_exponent=65537, key_size=settings.KEY_BITS)\n",
		"pkg/consts.go":      "package pkg\n\nconst DefaultBits = 1024\nvar minBits = 2048\n",
		"pkg/keys.go":        "package pkg\n\nfunc f() {\n\tk, _ := rsa.GenerateKey(rand.Reader, DefaultBits)\n\tj, _ := rsa.GenerateKey(rand.Reader, minBits)\n}\n",
	}
	assets, err := svc.fileAssets("t1", "s", "upload", "app.zip", "app.zip", zipOf(t, files))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"crypto_usage|DES|weak|src/Use.java:3", "crypto_usage|DES|weak|src/Use.java:4", "crypto_usage|MD5|weak|src/Use.java:6",
		"crypto_usage|RSA-1024|weak|lib/hasher.py:3", "crypto_usage|RSA-1024|weak|pkg/keys.go:4", "crypto_usage|SHA-1|weak|lib/hasher.py:2",
	}
	sort.Strings(want)
	if got := assetLines(assets, "app.zip!"); !reflect.DeepEqual(got, want) {
		t.Fatalf("across files\n got %q\nwant %q", got, want)
	}
	for _, a := range assets {
		if a.Location == "app.zip!/src/Use.java:3" && (a.Metadata["via"] != "CIPHER" || a.Metadata["defined_in"] != "app.zip!/src/Constants.java" || a.Metadata["archive"] != "app.zip" || a.Metadata["member"] != "src/Use.java") {
			t.Fatalf("resolved asset: %+v", a.Metadata)
		}
	}

	// The same over a repository's files, read one after another in any order.
	unit := newUsageUnit()
	var found []CryptoAsset
	for _, name := range []string{"src/Use.java", "src/Constants.java"} { // the reader before the definition
		a, _, _ := svc.fileAssetsIn(fileRef{unit: unit}, "t1", "s", "git", "repo/"+name, name, []byte(files[name]))
		found = append(found, a...)
	}
	late, _ := svc.unitAssets(unit, "t1", "s", "git")
	if got := assetLines(append(found, late...), "repo"); !reflect.DeepEqual(got, []string{"crypto_usage|DES|weak|src/Use.java:3", "crypto_usage|DES|weak|src/Use.java:4", "crypto_usage|MD5|weak|src/Use.java:6"}) {
		t.Fatalf("across a repository's files: %q", got)
	}
	if again, _ := svc.unitAssets(unit, "t1", "s", "git"); len(again) != 0 {
		t.Fatalf("a second resolve reported %d assets again", len(again))
	}

	// A file on its own resolves nothing from elsewhere, and a constant
	// with too many values across files is not one.
	if got := usageOf("Use.java", files["src/Use.java"]); !reflect.DeepEqual(got, []string{"MD5@6"}) {
		t.Fatalf("a file alone: %v", got)
	}
	many := map[string]string{"use.py": "h = hashlib.new(DIGEST)\n"}
	for i, v := range []string{"md5", "sha1", "md4", "sha256", "sha512"} {
		many["c"+itoa(i)+".py"] = "DIGEST = '" + v + "'\n"
	}
	if assets, _ := svc.fileAssets("t1", "s", "upload", "many.zip", "many.zip", zipOf(t, many)); len(assets) != 0 {
		t.Fatalf("a name with five values across files was resolved: %q", assetLines(assets, "many.zip!"))
	}
}

// A PEM block is found wherever it starts: after other bytes on its line,
// or inside a binary with no line break before it (9.2.0-beta).
func TestPEMIsFoundInTheMiddleOfALine(t *testing.T) {
	priv := testPrivatePEM(t)
	for name, raw := range map[string]string{
		"after text on the line": "key=" + priv,
		"in a binary":            strings.Repeat("\x00\x7f", 700) + priv + strings.Repeat("\x00", 64),
		"twice on one line":      "a " + priv[:len(priv)-1] + " b " + priv,
	} {
		got := findMaterial("blob.bin", []byte(raw))
		n := 0
		for _, f := range got {
			if f.kind == "private_key_material" && f.algorithm == "RSA-2048" {
				n++
			}
		}
		if want := map[bool]int{true: 2, false: 1}[name == "twice on one line"]; n != want {
			t.Fatalf("%s: %d keys, want %d (%+v)", name, n, want, got)
		}
	}
	// At the start of a line it is found once, as before.
	if got := findMaterial("k.pem", []byte(priv)); len(got) != 1 {
		t.Fatalf("a plain PEM file: %d findings", len(got))
	}
	// A marker with no block after it is nothing.
	if got := findMaterial("notes.bin", []byte("see -----BEGIN and -----END nothing")); len(got) != 0 {
		t.Fatalf("a bare marker: %+v", got)
	}

	// The same reading a large object through, with the block across the
	// window's edge and no line start before it.
	big := strings.Repeat("x", 4*maxPEMBlock-20) + priv + strings.Repeat("y\n", 100000) + "z" + priv
	found, err := streamPEM(strings.NewReader(big))
	if err != nil || len(found) != 2 || found[0].line != 1 || found[1].line != 100000+strings.Count(priv, "\n")+1 {
		t.Fatalf("read through: %v, %d found %+v", err, len(found), found)
	}
}
