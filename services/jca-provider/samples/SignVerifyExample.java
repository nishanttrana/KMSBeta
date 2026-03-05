import com.vecta.kms.VectaKMSProvider;

import java.security.KeyStore;
import java.security.Security;
import java.security.Signature;
import java.util.Base64;

/**
 * Example: Sign and verify data using Vecta KMS RSA key.
 */
public class SignVerifyExample {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new VectaKMSProvider());

        KeyStore ks = KeyStore.getInstance("VectaKMS", "VectaKMS");
        ks.load(null, null);

        String keyAlias = args.length > 0 ? args[0] : ks.aliases().nextElement();
        java.security.Key key = ks.getKey(keyAlias, null);

        byte[] data = "Sign this message with Vecta KMS".getBytes();

        // Sign
        Signature signer = Signature.getInstance("SHA256withRSA", "VectaKMS");
        signer.initSign((java.security.PrivateKey) key);
        signer.update(data);
        byte[] signature = signer.sign();
        System.out.println("Signature: " + Base64.getEncoder().encodeToString(signature));

        // Verify
        Signature verifier = Signature.getInstance("SHA256withRSA", "VectaKMS");
        verifier.initVerify((java.security.PublicKey) key);
        verifier.update(data);
        boolean valid = verifier.verify(signature);
        System.out.println("Valid: " + valid);
    }
}
