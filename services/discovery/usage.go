package main

import (
	"path/filepath"
	"regexp"
	"strings"

	"vecta-kms/pkg/cryptocatalog"
)

// Crypto usage in source and configuration files (7.36.0-beta). Key
// material says what keys exist; usage says what cryptography the code and
// servers are written to perform: a call that names an algorithm
// (Cipher.getInstance("DES"), hashlib.md5, crypto.createCipheriv("rc4")), a
// key size given at generation (rsa.GenerateKey(r, 1024)), and the
// protocols and suites a server configuration enables (ssl_protocols,
// SSLCipherSuite, sshd Ciphers). Each is an asset of type crypto_usage
// whose algorithm is the catalogue's name for what was named, so its class
// comes from pkg/cryptocatalog like every other asset's. A bare name with
// no parameter set ("RSA") is recorded and stays "not assessed".
//
// Detection is deterministic: a rule matches a call, import or directive,
// not a word, and comment lines are skipped, so a README that says "MD5"
// is not a finding. The line itself is never stored: the asset records the
// file, line, algorithm and which call or directive named it.

// usageRule matches one way of naming an algorithm. algs turns a match into
// the catalogue names it uses (none: not a finding).
type usageRule struct {
	api  string
	exts map[string]bool // file extensions; nil: any file usageFile admits
	re   *regexp.Regexp
	algs func(m []string) []string
}

func exts(list string) map[string]bool {
	m := map[string]bool{}
	for _, e := range strings.Fields(list) {
		m[e] = true
	}
	return m
}

var (
	javaLike   = exts(".java .kt .scala .groovy")
	pythonExt  = exts(".py")
	goExt      = exts(".go")
	jsExt      = exts(".js .ts .jsx .tsx .mjs .cjs")
	csExt      = exts(".cs")
	cExt       = exts(".c .h .cpp .cc .hpp")
	phpExt     = exts(".php")
	rubyExt    = exts(".rb")
	rustExt    = exts(".rs")
	scriptExt  = exts(".sh .ps1 .yaml .yml .tf .dockerfile")
	configExt  = exts(".conf .cfg .ini .properties .toml .xml .yaml .yml .json .env")
	commentsAt = map[string][]string{} // extension -> line comment markers
)

func init() {
	for _, e := range []string{".java", ".kt", ".scala", ".groovy", ".go", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".cs", ".c", ".h", ".cpp", ".cc", ".hpp", ".rs", ".php"} {
		commentsAt[e] = []string{"//", "/*", "*"}
	}
	for _, e := range []string{".py", ".rb", ".sh", ".yaml", ".yml", ".toml", ".conf", ".cfg", ".properties", ".tf", ".env", ".dockerfile", ""} {
		commentsAt[e] = []string{"#"}
	}
	commentsAt[".ini"] = []string{"#", ";"}
	commentsAt[".ps1"] = []string{"#"}
	commentsAt[".php"] = append(commentsAt[".php"], "#")
	commentsAt[".xml"] = []string{"<!--"}
}

// one returns its argument's algorithm, or none.
func one(name string) []string {
	if name == "" {
		return nil
	}
	return []string{name}
}

// cipherName maps a cipher, digest or transformation as libraries spell it
// (Java "DESede/CBC/PKCS5Padding", OpenSSL "des-ede3-cbc", "aes-128-ecb",
// "HmacSHA1", "SHA1withRSA") to the catalogue's name. An unknown name is
// returned upper-case, so it is recorded and not assessed.
func cipherName(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}
	// Java transformation: algorithm/mode/padding.
	if alg, rest, ok := strings.Cut(s, "/"); ok {
		mode, _, _ := strings.Cut(rest, "/")
		base := cipherName(alg)
		if mode == "ecb" && strings.HasPrefix(base, "AES") {
			return "AES-ECB"
		}
		return base
	}
	// Signature algorithms name their digest: SHA1withRSA, MD5withRSA.
	if dig, _, ok := strings.Cut(s, "with"); ok && dig != "" {
		return cipherName(dig)
	}
	switch {
	case strings.HasPrefix(s, "hmac"):
		if d := cipherName(strings.TrimLeft(strings.TrimPrefix(s, "hmac"), "-_")); strings.HasPrefix(d, "SHA") || d == "MD5" {
			return "HMAC-" + d
		}
		return strings.ToUpper(s)
	case s == "md5", s == "md4":
		return strings.ToUpper(s)
	case s == "sha1", s == "sha-1", s == "sha":
		return "SHA-1"
	case s == "sha224", s == "sha-224", s == "sha256", s == "sha-256", s == "sha384", s == "sha-384", s == "sha512", s == "sha-512":
		return "SHA-" + strings.TrimLeft(strings.TrimPrefix(s, "sha"), "-")
	case strings.HasPrefix(s, "des-ede3"), strings.HasPrefix(s, "des3"), s == "desede", s == "tripledes", s == "3des", strings.HasPrefix(s, "des-ede"):
		return "3DES"
	case s == "des" || strings.HasPrefix(s, "des-"):
		return "DES"
	case strings.HasPrefix(s, "rc4") || s == "arcfour" || s == "arc4":
		return "RC4"
	case strings.HasPrefix(s, "rc2"):
		return "RC2"
	case s == "blowfish" || s == "bf" || strings.HasPrefix(s, "bf-"):
		return "Blowfish"
	case strings.HasPrefix(s, "cast5") || strings.HasPrefix(s, "cast-"):
		return "CAST5"
	case s == "idea" || strings.HasPrefix(s, "idea-"):
		return "IDEA"
	case strings.HasPrefix(s, "aes"):
		// aes-128-ecb, aes256, aes-256-gcm; "aes" alone is not assessed
		// (Java's provider default is handled by its rule).
		t := strings.ReplaceAll(strings.TrimPrefix(s, "aes"), "_", "-")
		t = strings.TrimPrefix(t, "-")
		if t == "" {
			return "AES"
		}
		size, mode, _ := strings.Cut(t, "-")
		if mode == "" && (size == "ecb" || size == "cbc" || size == "gcm" || size == "ctr") {
			if size == "ecb" {
				return "AES-ECB"
			}
			return "AES"
		}
		return strings.ToUpper("AES-" + size + strings.TrimSuffix("-"+mode, "-"))
	case strings.HasPrefix(s, "chacha20"):
		return "CHACHA20-POLY1305"
	}
	return strings.ToUpper(s)
}

// tokens returns the names in a configuration value that are switched on:
// a name prefixed by "!" or "-" is excluded, and "+" adds.
func enabledTokens(v string) []string {
	var out []string
	for _, t := range strings.FieldsFunc(v, func(r rune) bool {
		return r == ' ' || r == ':' || r == ',' || r == '\t' || r == '"' || r == '\'' || r == ';'
	}) {
		if t == "" || t[0] == '!' || t[0] == '-' {
			continue
		}
		out = append(out, strings.TrimPrefix(t, "+"))
	}
	return out
}

// protocolNames keeps the SSL/TLS versions a configuration value enables.
func protocolNames(v string) []string {
	var out []string
	for _, t := range enabledTokens(v) {
		if reProtoToken.MatchString(t) {
			out = append(out, strings.ToUpper(strings.ReplaceAll(t, "_", ".")))
		}
	}
	return out
}

var reProtoToken = regexp.MustCompile(`(?i)^(SSLv[23]|TLSv1(?:\.[0-3])?|TLS1[._]?[0-3])$`)

// suiteNames turns an OpenSSL cipher string into the weak primitives its
// enabled entries name. Strong suites are not listed one by one: a server's
// negotiated suite is what the network scan records.
func suiteNames(v string) []string {
	var out []string
	for _, t := range enabledTokens(v) {
		u := strings.ToUpper(t)
		switch {
		case strings.Contains(u, "RC4"):
			out = append(out, "RC4")
		case strings.Contains(u, "DES-CBC3"), strings.Contains(u, "3DES"):
			out = append(out, "3DES")
		case strings.Contains(u, "DES"):
			out = append(out, "DES")
		case u == "MD5" || strings.HasSuffix(u, "-MD5"):
			out = append(out, "MD5")
		case strings.Contains(u, "IDEA"):
			out = append(out, "IDEA")
		}
	}
	return out
}

// sshNames maps an sshd/ssh_config algorithm list to catalogue names.
func sshNames(kind string) func(m []string) []string {
	return func(m []string) []string {
		var out []string
		for _, t := range enabledTokens(m[1]) {
			switch kind {
			case "kex":
				if alg, _ := sshKexName(t); alg != "" {
					out = append(out, alg)
				}
			default:
				out = append(out, sshSymName(t))
			}
		}
		return out
	}
}

func rsaBits(m []string) []string { return one("RSA-" + m[1]) }

func ecCurve(m []string) []string {
	c := strings.ToLower(m[1])
	for _, n := range []string{"521", "384", "256", "224"} {
		if strings.Contains(c, n) {
			return one("EC-P" + n)
		}
	}
	return nil
}

func fixed(names ...string) func([]string) []string {
	return func([]string) []string { return names }
}

// first names what the call's argument names. A password-based scheme
// (PBEWithMD5AndDES) uses both its digest and its cipher.
func first(m []string) []string {
	if rest, ok := strings.CutPrefix(strings.ToLower(m[1]), "pbewith"); ok {
		dig, cipher, _ := strings.Cut(rest, "and")
		return append(one(cipherName(dig)), one(cipherName(cipher))...)
	}
	return one(cipherName(m[1]))
}

var usageRules = []usageRule{
	// Java and the JVM: JCA lookups by name. Cipher.getInstance("AES") is
	// AES/ECB/PKCS5Padding in the JDK's providers.
	{"Cipher.getInstance", javaLike, regexp.MustCompile(`Cipher\.getInstance\(\s*"([^"]+)"`), func(m []string) []string {
		if strings.EqualFold(m[1], "AES") {
			return one("AES-ECB")
		}
		return first(m)
	}},
	{"MessageDigest.getInstance", javaLike, regexp.MustCompile(`MessageDigest\.getInstance\(\s*"([^"]+)"`), first},
	{"Mac.getInstance", javaLike, regexp.MustCompile(`Mac\.getInstance\(\s*"([^"]+)"`), first},
	{"Signature.getInstance", javaLike, regexp.MustCompile(`Signature\.getInstance\(\s*"([^"]+)"`), first},
	{"KeyGenerator.getInstance", javaLike, regexp.MustCompile(`KeyGenerator\.getInstance\(\s*"(DES|DESede|RC2|RC4|ARCFOUR|Blowfish|HmacMD5|HmacSHA1)"`), first},
	{"SSLContext.getInstance", javaLike, regexp.MustCompile(`SSLContext\.getInstance\(\s*"(SSLv3|TLSv1(?:\.[0-3])?)"`), func(m []string) []string { return protocolNames(m[1]) }},

	// Python: hashlib, PyCryptodome and pyca/cryptography.
	{"hashlib", pythonExt, regexp.MustCompile(`\bhashlib\.(md5|sha1|md4)\(`), first},
	{"hashlib.new", pythonExt, regexp.MustCompile(`\bhashlib\.new\(\s*['"]([A-Za-z0-9_-]+)['"]`), first},
	{"Crypto.Cipher", pythonExt, regexp.MustCompile(`\b(DES3|DES|ARC4|ARC2|Blowfish|CAST)\.new\(`), func(m []string) []string {
		return one(map[string]string{"DES3": "3DES", "DES": "DES", "ARC4": "RC4", "ARC2": "RC2", "Blowfish": "Blowfish", "CAST": "CAST5"}[m[1]])
	}},
	{"AES.MODE_ECB", pythonExt, regexp.MustCompile(`\bAES\.MODE_ECB\b`), fixed("AES-ECB")},
	{"cryptography algorithms", pythonExt, regexp.MustCompile(`\balgorithms\.(TripleDES|ARC4|Blowfish|CAST5|IDEA)\(`), first},
	{"cryptography hashes", pythonExt, regexp.MustCompile(`\bhashes\.(MD5|SHA1)\(`), first},
	{"generate_private_key", pythonExt, regexp.MustCompile(`rsa\.generate_private_key\([^)]*key_size\s*=\s*(\d{3,5})`), rsaBits},
	{"ec curve", pythonExt, regexp.MustCompile(`\bec\.(SECP\d{3}R1)\(`), ecCurve},
	{"ssl.PROTOCOL", pythonExt, regexp.MustCompile(`\bssl\.PROTOCOL_(SSLv3|TLSv1(?:_[12])?)\b`), func(m []string) []string { return protocolNames(m[1]) }},

	// Go: calls, not imports (the des package also provides 3DES).
	{"md5 (Go)", goExt, regexp.MustCompile(`\bmd5\.(?:New|Sum)\(`), fixed("MD5")},
	{"sha1 (Go)", goExt, regexp.MustCompile(`\bsha1\.(?:New|Sum)\(`), fixed("SHA-1")},
	{"des (Go)", goExt, regexp.MustCompile(`\bdes\.(NewTripleDESCipher|NewCipher)\(`), func(m []string) []string {
		return one(map[string]string{"NewTripleDESCipher": "3DES", "NewCipher": "DES"}[m[1]])
	}},
	{"rc4 (Go)", goExt, regexp.MustCompile(`\brc4\.NewCipher\(`), fixed("RC4")},
	{"rsa.GenerateKey", goExt, regexp.MustCompile(`\brsa\.GenerateKey\([^,]+,\s*(\d{3,5})\)`), rsaBits},
	{"elliptic curve", goExt, regexp.MustCompile(`\b(?:elliptic|ecdh)\.(P\d{3})\(`), ecCurve},
	{"tls.Config", goExt, regexp.MustCompile(`\btls\.Version(SSL30|TLS10|TLS11)\b`), func(m []string) []string {
		return one(map[string]string{"SSL30": "SSL-3.0", "TLS10": "TLS-1.0", "TLS11": "TLS-1.1"}[m[1]])
	}},

	// JavaScript and TypeScript (Node crypto).
	{"crypto.createHash", jsExt, regexp.MustCompile(`create(?:Hash|Hmac)\(\s*['"]([A-Za-z0-9_-]+)['"]`), first},
	{"crypto.createCipheriv", jsExt, regexp.MustCompile(`create(?:Cipher|Decipher)(?:iv)?\(\s*['"]([A-Za-z0-9_-]+)['"]`), first},
	{"generateKeyPair", jsExt, regexp.MustCompile(`modulusLength\s*:\s*(\d{3,5})`), rsaBits},
	{"namedCurve", jsExt, regexp.MustCompile(`namedCurve\s*:\s*['"]((?:prime|secp|P-)\d{3}\w*)['"]`), ecCurve},

	// C#.
	{".NET", csExt, regexp.MustCompile(`\b(MD5|SHA1|DES|TripleDES|RC2)(?:\.Create\(|CryptoServiceProvider\b|Managed\b)`), first},
	{".NET HMAC", csExt, regexp.MustCompile(`\bnew\s+HMAC(MD5|SHA1)\b`), func(m []string) []string { return one("HMAC-" + cipherName(m[1])) }},
	{"CipherMode.ECB", csExt, regexp.MustCompile(`\bCipherMode\.ECB\b`), fixed("AES-ECB")},
	{"RSACryptoServiceProvider", csExt, regexp.MustCompile(`RSACryptoServiceProvider\(\s*(\d{3,5})\s*\)`), rsaBits},
	{"SslProtocols", csExt, regexp.MustCompile(`SslProtocols\.(Ssl3|Tls|Tls11)\b`), func(m []string) []string {
		return one(map[string]string{"Ssl3": "SSL-3.0", "Tls": "TLS-1.0", "Tls11": "TLS-1.1"}[m[1]])
	}},

	// C and C++ (OpenSSL).
	{"OpenSSL EVP", cExt, regexp.MustCompile(`\bEVP_(md5|md4|sha1|des_ede3\w*|des_\w+|rc4\w*|rc2_\w+|bf_\w+|cast5_\w+|idea_\w+|aes_(?:128|192|256)_ecb)\(`), func(m []string) []string {
		n := strings.ReplaceAll(m[1], "_", "-")
		return one(cipherName(n))
	}},
	{"OpenSSL MD5", cExt, regexp.MustCompile(`\b(MD5|SHA1|MD4)_Init\(`), first},
	{"RSA_generate_key", cExt, regexp.MustCompile(`RSA_generate_key(?:_ex)?\(\s*[^,]*?,?\s*(\d{3,5})\s*,`), rsaBits},

	// PHP, Ruby, Rust.
	{"hash()", phpExt, regexp.MustCompile(`\bhash(?:_hmac)?\(\s*['"](md5|sha1|md4)['"]`), first},
	{"md5()", phpExt, regexp.MustCompile(`(?:^|[^\w>$:])(md5|sha1)\(`), first},
	{"openssl_encrypt", phpExt, regexp.MustCompile(`openssl_(?:en|de)crypt\([^,]+,\s*['"]([A-Za-z0-9-]+)['"]`), first},
	{"Digest", rubyExt, regexp.MustCompile(`\bDigest::(MD5|SHA1)\b`), first},
	{"OpenSSL::Cipher", rubyExt, regexp.MustCompile(`OpenSSL::Cipher\.new\(\s*['"]([A-Za-z0-9-]+)['"]`), first},
	{"md5/sha1 crate", rustExt, regexp.MustCompile(`\b(Md5|Sha1)::new\(|\bmd5::compute\(`), func(m []string) []string {
		if m[1] == "Sha1" {
			return one("SHA-1")
		}
		return one("MD5")
	}},

	// Shell and infrastructure code: key generation with a size.
	{"openssl genrsa", scriptExt, regexp.MustCompile(`openssl\s+genrsa\b[^\n|]*?\s(\d{3,5})\b`), rsaBits},
	{"rsa_keygen_bits", nil, regexp.MustCompile(`rsa_keygen_bits:(\d{3,5})`), rsaBits},
	{"ssh-keygen", scriptExt, regexp.MustCompile(`ssh-keygen\b[^\n]*-t\s+rsa\b[^\n]*-b\s+(\d{3,5})`), rsaBits},
	{"ssh-keygen dsa", scriptExt, regexp.MustCompile(`ssh-keygen\b[^\n]*-t\s+dsa\b`), fixed("DSA")},
	{"key_size", exts(".tf"), regexp.MustCompile(`rsa_bits\s*=\s*(\d{3,5})`), rsaBits},

	// Server configuration: protocols and suites a server enables.
	{"ssl_protocols", nil, regexp.MustCompile(`(?i)^\s*(?:ssl_protocols|SSLProtocol|MinProtocol|Protocols?|ssl\.enabled\.protocols|tls[_.-]?min[_.-]?version|minimumTlsVersion|sslProtocols?)\s*[=:]?\s*(.+)$`), func(m []string) []string { return protocolNames(m[1]) }},
	{"ssl_ciphers", nil, regexp.MustCompile(`(?i)^\s*(?:ssl_ciphers|SSLCipherSuite|CipherString|ssl\.cipher\.suites|ciphers?)\s*[=:]?\s*(.+)$`), func(m []string) []string { return suiteNames(m[1]) }},
	{"sshd Ciphers", nil, regexp.MustCompile(`^\s*Ciphers\s+(\S.*)$`), sshNames("cipher")},
	{"sshd MACs", nil, regexp.MustCompile(`^\s*MACs\s+(\S.*)$`), sshNames("mac")},
	{"sshd KexAlgorithms", nil, regexp.MustCompile(`^\s*KexAlgorithms\s+(\S.*)$`), sshNames("kex")},
}

// usageFile: a file whose lines the usage rules read, and its extension
// (sshd_config and similar names count as configuration).
func usageFile(name string) (string, bool) {
	base := strings.ToLower(filepath.Base(name))
	switch base {
	case "sshd_config", "ssh_config", "nginx.conf", "httpd.conf", "ssl.conf", "openssl.cnf", "dockerfile":
		return "", true
	}
	ext := filepath.Ext(base)
	if strings.HasPrefix(base, ".env") {
		ext = ".env"
	}
	for _, set := range []map[string]bool{javaLike, pythonExt, goExt, jsExt, csExt, cExt, phpExt, rubyExt, rustExt, scriptExt, configExt} {
		if set[ext] {
			return ext, true
		}
	}
	return "", false
}

// isComment: a line that is only a comment in the file's language.
func isComment(ext, line string) bool {
	t := strings.TrimSpace(line)
	for _, c := range commentsAt[ext] {
		if strings.HasPrefix(t, c) {
			return true
		}
	}
	return false
}

// maxUsageLine skips minified or generated lines.
const maxUsageLine = 2000

// usageFindings applies the rules to one line of a file.
func usageFindings(ext, line string, n int) []finding {
	if len(line) > maxUsageLine || isComment(ext, line) {
		return nil
	}
	var out []finding
	seen := map[string]bool{}
	for _, r := range usageRules {
		if r.exts != nil && !r.exts[ext] {
			continue
		}
		if r.exts == nil && !configExt[ext] && ext != "" && !scriptExt[ext] {
			// Directive rules read configuration and scripts, not code.
			continue
		}
		for _, m := range r.re.FindAllStringSubmatch(line, -1) {
			for _, alg := range r.algs(m) {
				// The catalogue's own spelling (TLSv1 -> TLS-1.0, 3DES -> 3TDEA).
				if e, ok := cryptocatalog.Lookup(alg); ok {
					alg = e.Algorithm
				}
				if alg == "" || seen[alg] {
					continue
				}
				seen[alg] = true
				out = append(out, finding{kind: "crypto_usage", algorithm: alg, name: alg + " · " + r.api, line: n, meta: map[string]interface{}{"api": r.api}})
			}
		}
	}
	return out
}
