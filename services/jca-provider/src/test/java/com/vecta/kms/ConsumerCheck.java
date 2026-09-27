package com.vecta.kms;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidKeyException;
import java.security.Security;
import java.util.Arrays;

/**
 * A real JCA consumer of the provider: registers it with java.security,
 * obtains the cipher through javax.crypto.Cipher, and round-trips a key
 * through Vecta KMS. Run by services/ekm/jca_consumer_test.go against the
 * ekm HTTP API over TLS; prints OK or exits non-zero.
 *
 * Args: keyId badToken
 */
public final class ConsumerCheck {

    public static void main(String[] args) throws Exception {
        String keyId = args[0];
        Security.addProvider(new VectaKMSProvider());

        // Found through the JCA by name, not constructed directly.
        Cipher wrap = Cipher.getInstance(VectaKMSProvider.KEY_WRAP, VectaKMSProvider.NAME);
        check(Cipher.getInstance(VectaKMSProvider.KEY_WRAP).getProvider().getName().equals(VectaKMSProvider.NAME),
                "provider lookup by algorithm");

        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(256);
        SecretKey dataKey = gen.generateKey();

        wrap.init(Cipher.WRAP_MODE, new VectaKMSKey(keyId));
        byte[] wrapped = wrap.wrap(dataKey);
        byte[] iv = wrap.getIV();
        check(wrapped.length > 0 && !Arrays.equals(wrapped, dataKey.getEncoded()), "wrapped key differs from the key");

        Cipher unwrap = Cipher.getInstance(VectaKMSProvider.KEY_WRAP, VectaKMSProvider.NAME);
        if (iv == null) {
            unwrap.init(Cipher.UNWRAP_MODE, new VectaKMSKey(keyId));
        } else {
            unwrap.init(Cipher.UNWRAP_MODE, new VectaKMSKey(keyId), new IvParameterSpec(iv));
        }
        SecretKey back = (SecretKey) unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        check(Arrays.equals(back.getEncoded(), dataKey.getEncoded()), "unwrapped key equals the original");
        check("AES".equals(back.getAlgorithm()), "unwrapped key algorithm");

        // Bulk encryption is not offered, rather than faked.
        boolean refused = false;
        try {
            Cipher.getInstance(VectaKMSProvider.KEY_WRAP, VectaKMSProvider.NAME).init(Cipher.ENCRYPT_MODE, new VectaKMSKey(keyId));
        } catch (UnsupportedOperationException expected) {
            refused = true;
        }
        check(refused, "ENCRYPT_MODE is refused");

        // A key the tenant does not have is refused by the KMS.
        refused = false;
        try {
            Cipher c = Cipher.getInstance(VectaKMSProvider.KEY_WRAP, VectaKMSProvider.NAME);
            c.init(Cipher.WRAP_MODE, new VectaKMSKey("no-such-key"));
            c.wrap(dataKey);
        } catch (InvalidKeyException expected) {
            refused = expected.getMessage().contains("refused");
        }
        check(refused, "unknown key is refused by the KMS");
        System.out.println("OK");
    }

    private static void check(boolean ok, String what) {
        if (!ok) {
            System.err.println("FAIL: " + what);
            System.exit(1);
        }
    }
}
