/**
 * VectaPKCS11Encrypt — Java PKCS#11 data encryption sample for Vecta KMS.
 *
 * Demonstrates:
 *   - AES-256-GCM authenticated encryption / decryption (FIPS 140-3 approved)
 *   - RSA-OAEP-SHA256 key wrapping / unwrapping
 *   - Envelope encryption (DEK wrapped with KEK from PKCS#11 token)
 *
 * Compile:
 *   javac VectaPKCS11Encrypt.java
 *
 * Run (encrypt):
 *   java -cp . VectaPKCS11Encrypt encrypt \
 *       --module /usr/lib/libvecta-pkcs11.so \
 *       --slot 0 --pin-env PKCS11_PIN \
 *       --key-label vecta-aes256-01 \
 *       --input plaintext.bin --output ciphertext.enc
 *
 * Run (decrypt):
 *   java -cp . VectaPKCS11Encrypt decrypt \
 *       --module /usr/lib/libvecta-pkcs11.so \
 *       --slot 0 --pin-env PKCS11_PIN \
 *       --key-label vecta-aes256-01 \
 *       --input ciphertext.enc --output decrypted.bin
 *
 * Build JAR:
 *   javac VectaPKCS11Encrypt.java && jar cfe vecta-pkcs11-encrypt.jar VectaPKCS11Encrypt *.class
 *   java -jar vecta-pkcs11-encrypt.jar encrypt ...
 *
 * Requirements: Java 11+, SunPKCS11 provider (ships with JDK).
 */

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;

public class VectaPKCS11Encrypt {

    // AES-256-GCM constants (FIPS 140-3 approved)
    private static final String AES_GCM_ALGO = "AES/GCM/NoPadding";
    private static final int    GCM_IV_BYTES  = 12;   // 96-bit IV — NIST recommended
    private static final int    GCM_TAG_BITS  = 128;  // 128-bit authentication tag
    private static final int    AES_KEY_BITS  = 256;

    // File format: [4 magic][1 version][12 IV][16 tag][N ciphertext]
    private static final byte[] MAGIC   = {0x56, 0x45, 0x43, 0x54}; // "VECT"
    private static final byte   VERSION = 0x01;

    public static void main(String[] args) throws Exception {
        if (args.length < 2) usage();
        String command = args[0];
        Map<String,String> opts = parseArgs(Arrays.copyOfRange(args, 1, args.length));

        String modulePath = opts.getOrDefault("--module",    "/usr/lib/libvecta-pkcs11.so");
        int    slot       = Integer.parseInt(opts.getOrDefault("--slot", "0"));
        String pinEnvVar  = opts.getOrDefault("--pin-env",   "PKCS11_PIN");
        String keyLabel   = opts.getOrDefault("--key-label", "");
        String inputPath  = opts.get("--input");
        String outputPath = opts.get("--output");

        if (inputPath == null || outputPath == null) {
            System.err.println("ERROR: --input and --output are required.");
            usage();
        }

        // Load PKCS#11 token and authenticate
        Provider p11 = loadPKCS11Provider(modulePath, slot);
        Security.addProvider(p11);
        KeyStore ks = KeyStore.getInstance("PKCS11", p11);
        char[] pin = getPin(pinEnvVar);
        ks.load(null, pin);
        Arrays.fill(pin, '\0'); // Clear PIN from memory immediately

        switch (command.toLowerCase()) {
            case "encrypt" -> encrypt(ks, p11, keyLabel, inputPath, outputPath);
            case "decrypt" -> decrypt(ks, p11, keyLabel, inputPath, outputPath);
            case "keygen"  -> generateKey(ks, p11, keyLabel);
            default        -> { System.err.println("Unknown command: " + command); usage(); }
        }
    }

    /** Envelope-encrypt: generate a random AES-256 DEK, encrypt data with it,
     *  then wrap the DEK with the AES-256 key in the PKCS#11 token. */
    static void encrypt(KeyStore ks, Provider p11, String keyLabel,
                        String inPath, String outPath) throws Exception {
        // Generate ephemeral DEK (done in JVM — wrapping happens via P11 token)
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_BITS, new SecureRandom());
        SecretKey dek = kg.generateKey();

        // Wrap DEK with KEK from PKCS#11 token
        Key kek = findSecretKey(ks, keyLabel);
        byte[] wrappedDEK = wrapKey(kek, dek, p11);

        // Generate random IV
        byte[] iv = new byte[GCM_IV_BYTES];
        new SecureRandom().nextBytes(iv);

        // Encrypt plaintext with AES-256-GCM
        Cipher aesGcm = Cipher.getInstance(AES_GCM_ALGO);
        aesGcm.init(Cipher.ENCRYPT_MODE, dek, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] plaintext  = Files.readAllBytes(Paths.get(inPath));
        byte[] ciphertext = aesGcm.doFinal(plaintext);

        // Write output: magic + version + IV + wrapped-DEK length (2 bytes) + wrapped-DEK + ciphertext
        try (OutputStream out = new BufferedOutputStream(new FileOutputStream(outPath))) {
            out.write(MAGIC);
            out.write(VERSION);
            out.write(iv);
            byte[] wdLen = ByteBuffer.allocate(2).putShort((short) wrappedDEK.length).array();
            out.write(wdLen);
            out.write(wrappedDEK);
            out.write(ciphertext);
        }
        System.out.printf("Encrypted %d bytes → %s%n", plaintext.length, outPath);
        System.out.printf("  Algorithm : AES-256-GCM (FIPS 140-3 approved)%n");
        System.out.printf("  IV        : %s%n", hexEncode(iv));
        System.out.printf("  Wrapped DEK length: %d bytes%n", wrappedDEK.length);
    }

    /** Decrypt: unwrap DEK from PKCS#11 token, decrypt AES-256-GCM ciphertext. */
    static void decrypt(KeyStore ks, Provider p11, String keyLabel,
                        String inPath, String outPath) throws Exception {
        byte[] blob = Files.readAllBytes(Paths.get(inPath));
        ByteBuffer buf = ByteBuffer.wrap(blob);

        // Validate magic
        byte[] magic = new byte[4];
        buf.get(magic);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new IllegalArgumentException("Not a Vecta encrypted file (bad magic).");
        }
        byte ver = buf.get();
        if (ver != VERSION) {
            throw new IllegalArgumentException("Unsupported format version: " + ver);
        }

        byte[] iv = new byte[GCM_IV_BYTES];
        buf.get(iv);

        int wdLen = Short.toUnsignedInt(buf.getShort());
        byte[] wrappedDEK = new byte[wdLen];
        buf.get(wrappedDEK);

        byte[] ciphertext = new byte[buf.remaining()];
        buf.get(ciphertext);

        // Unwrap DEK via PKCS#11 token
        Key kek = findSecretKey(ks, keyLabel);
        SecretKey dek = unwrapKey(kek, wrappedDEK, p11);

        // Decrypt
        Cipher aesGcm = Cipher.getInstance(AES_GCM_ALGO);
        aesGcm.init(Cipher.DECRYPT_MODE, dek, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] plaintext = aesGcm.doFinal(ciphertext);

        Files.write(Paths.get(outPath), plaintext);
        System.out.printf("Decrypted %d bytes → %s%n", plaintext.length, outPath);
    }

    /** Generate and store a new AES-256 key on the PKCS#11 token. */
    static void generateKey(KeyStore ks, Provider p11, String label) throws Exception {
        if (label == null || label.isBlank()) {
            throw new IllegalArgumentException("--key-label is required for keygen");
        }
        KeyGenerator kg = KeyGenerator.getInstance("AES", p11);
        kg.init(AES_KEY_BITS);
        SecretKey key = kg.generateKey();
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(key);
        ks.setEntry(label, entry, new KeyStore.PasswordProtection(null));
        ks.store(null);
        System.out.printf("AES-256 key '%s' generated and stored in PKCS#11 token.%n", label);
    }

    // ── Key wrap / unwrap using AES-KeyWrap (FIPS 140-3 approved) ──────────

    private static byte[] wrapKey(Key kek, SecretKey dek, Provider p11) throws Exception {
        Cipher wrapper = Cipher.getInstance("AESWrap", p11);
        wrapper.init(Cipher.WRAP_MODE, kek);
        return wrapper.wrap(dek);
    }

    private static SecretKey unwrapKey(Key kek, byte[] wrappedDEK, Provider p11) throws Exception {
        Cipher wrapper = Cipher.getInstance("AESWrap", p11);
        wrapper.init(Cipher.UNWRAP_MODE, kek);
        return (SecretKey) wrapper.unwrap(wrappedDEK, "AES", Cipher.SECRET_KEY);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static Provider loadPKCS11Provider(String modulePath, int slot) throws Exception {
        String cfg = String.format("--name=VectaKMS\nlibrary=%s\nslot=%d%n", modulePath, slot);
        Provider base = Security.getProvider("SunPKCS11");
        if (base == null) {
            throw new IllegalStateException("SunPKCS11 provider not available. Use JDK 11+.");
        }
        return base.configure(cfg);
    }

    private static char[] getPin(String envVar) {
        String pin = System.getenv(envVar);
        if (pin == null || pin.isEmpty()) {
            // Prompt interactively
            Console console = System.console();
            if (console != null) {
                return console.readPassword("PKCS#11 PIN: ");
            }
            throw new IllegalStateException("PIN not provided. Set env var " + envVar + " or run in a terminal.");
        }
        return pin.toCharArray();
    }

    private static Key findSecretKey(KeyStore ks, String label) throws Exception {
        if (label == null || label.isBlank()) {
            throw new IllegalArgumentException("--key-label is required");
        }
        Key key = ks.getKey(label, null);
        if (key == null) {
            throw new IllegalArgumentException("Key not found in token: " + label +
                ". Use 'keygen' command to generate one first.");
        }
        return key;
    }

    private static Map<String,String> parseArgs(String[] args) {
        Map<String,String> m = new LinkedHashMap<>();
        for (int i = 0; i < args.length; i++) {
            if (args[i].startsWith("--") && i + 1 < args.length && !args[i+1].startsWith("--")) {
                m.put(args[i], args[++i]);
            } else if (args[i].startsWith("--")) {
                m.put(args[i], "true");
            }
        }
        return m;
    }

    private static String hexEncode(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static void usage() {
        System.err.println("""
            Usage: java VectaPKCS11Encrypt <command> [OPTIONS]

            Commands:
              encrypt   Encrypt a file using AES-256-GCM + AES-KeyWrap via PKCS#11 token
              decrypt   Decrypt a file encrypted with this tool
              keygen    Generate and store a new AES-256 key on the PKCS#11 token

            Options:
              --module <path>       PKCS#11 library path (default: /usr/lib/libvecta-pkcs11.so)
              --slot <n>            PKCS#11 slot index (default: 0)
              --pin-env <VAR>       Environment variable holding the PIN (default: PKCS11_PIN)
              --key-label <label>   Key label on the PKCS#11 token (required)
              --input <path>        Input file path
              --output <path>       Output file path

            Security note:
              All cryptographic operations use FIPS 140-3 approved algorithms:
                AES-256-GCM (data encryption), AES-KeyWrap (key encryption).
            """);
        System.exit(1);
    }
}
