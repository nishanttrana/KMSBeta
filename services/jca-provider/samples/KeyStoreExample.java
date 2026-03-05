import com.vecta.kms.VectaKMSProvider;

import java.security.KeyStore;
import java.security.Security;
import java.util.Enumeration;

/**
 * Example: List all keys from Vecta KMS via JCA KeyStore.
 */
public class KeyStoreExample {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new VectaKMSProvider());

        KeyStore ks = KeyStore.getInstance("VectaKMS", "VectaKMS");
        ks.load(null, null);

        System.out.println("Keys in Vecta KMS (" + ks.size() + "):");
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            java.security.Key key = ks.getKey(alias, null);
            System.out.printf("  - %s (algo=%s, format=%s)%n", alias, key.getAlgorithm(), key.getFormat());
        }
    }
}
