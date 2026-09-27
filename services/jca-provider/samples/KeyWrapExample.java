import com.vecta.kms.VectaKMSKey;
import com.vecta.kms.VectaKMSProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.Security;
import java.util.Arrays;

/** Wraps a fresh AES data key under a Vecta KMS TDE key and unwraps it. Args: tdeKeyId */
public class KeyWrapExample {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new VectaKMSProvider());
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(256);
        SecretKey dataKey = gen.generateKey();

        Cipher c = Cipher.getInstance(VectaKMSProvider.KEY_WRAP, VectaKMSProvider.NAME);
        c.init(Cipher.WRAP_MODE, new VectaKMSKey(args[0]));
        byte[] wrapped = c.wrap(dataKey);
        byte[] iv = c.getIV();

        if (iv == null) {
            c.init(Cipher.UNWRAP_MODE, new VectaKMSKey(args[0]));
        } else {
            c.init(Cipher.UNWRAP_MODE, new VectaKMSKey(args[0]), new IvParameterSpec(iv));
        }
        SecretKey back = (SecretKey) c.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        System.out.println("round trip: " + Arrays.equals(back.getEncoded(), dataKey.getEncoded()));
    }
}
