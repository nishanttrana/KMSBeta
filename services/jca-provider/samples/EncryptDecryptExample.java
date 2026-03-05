import com.vecta.kms.VectaKMSProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.security.KeyStore;
import java.security.Security;
import java.util.Base64;

/**
 * Example: Encrypt and decrypt data using Vecta KMS JCA provider.
 *
 * Set environment variables before running:
 *   export VECTA_BASE_URL=https://kms.example.com/svc/ekm
 *   export VECTA_TENANT_ID=root
 *   export VECTA_AUTH_TOKEN=your-token
 */
public class EncryptDecryptExample {
    public static void main(String[] args) throws Exception {
        // Register provider
        Security.addProvider(new VectaKMSProvider());

        // Load KeyStore to get key reference
        KeyStore ks = KeyStore.getInstance("VectaKMS", "VectaKMS");
        ks.load(null, null);

        String keyAlias = args.length > 0 ? args[0] : ks.aliases().nextElement();
        System.out.println("Using key: " + keyAlias);

        java.security.Key key = ks.getKey(keyAlias, null);

        // Encrypt
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "VectaKMS");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        byte[] plaintext = "Hello from Vecta JCA Provider!".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);

        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(ciphertext));

        // Decrypt
        Cipher decipher = Cipher.getInstance("AES/GCM/NoPadding", "VectaKMS");
        decipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] decrypted = decipher.doFinal(ciphertext);

        System.out.println("Decrypted: " + new String(decrypted));
    }
}
