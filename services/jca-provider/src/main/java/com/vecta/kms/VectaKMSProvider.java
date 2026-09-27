package com.vecta.kms;

import com.vecta.kms.internal.KMSHttpClient;
import com.vecta.kms.spi.VectaKeyWrapCipherSpi;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Vecta KMS JCA provider.
 *
 * <p>Registers one service, {@code Cipher.VectaKeyWrap}: it wraps and unwraps
 * keys under a Vecta KMS TDE key through the ekm service
 * ({@code POST /ekm/tde/keys/{id}/wrap} and {@code .../unwrap}). The Vecta key
 * never leaves the KMS; only the wrapped key comes back. Nothing else is
 * offered: there is no local cipher, signature or key store.
 *
 * <pre>{@code
 * Security.addProvider(new VectaKMSProvider());
 * Cipher c = Cipher.getInstance(VectaKMSProvider.KEY_WRAP, VectaKMSProvider.NAME);
 * c.init(Cipher.WRAP_MODE, new VectaKMSKey("tde_key_123"));
 * byte[] wrapped = c.wrap(dataKey);
 * byte[] iv = c.getIV();              // keep with the wrapped key
 * c.init(Cipher.UNWRAP_MODE, new VectaKMSKey("tde_key_123"), new IvParameterSpec(iv));
 * SecretKey back = (SecretKey) c.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
 * }</pre>
 *
 * <p>Configuration: {@link VectaKMSConfig#fromEnvironment()} for the no-arg
 * constructor, or pass a {@link VectaKMSConfig}.
 */
public final class VectaKMSProvider extends Provider {

    private static final long serialVersionUID = 2L;
    public static final String NAME = "VectaKMS";
    public static final String KEY_WRAP = "VectaKeyWrap";

    private final transient VectaKMSConfig config;
    private transient KMSHttpClient client;

    /** Reads its configuration from the environment on first use. */
    public VectaKMSProvider() {
        this(null);
    }

    public VectaKMSProvider(VectaKMSConfig config) {
        super(NAME, "2.0", "Vecta KMS key wrapping (Cipher " + KEY_WRAP + ")");
        this.config = config;
        putService(new KeyWrapService(this));
    }

    synchronized KMSHttpClient client() {
        if (client == null) {
            client = new KMSHttpClient(config != null ? config : VectaKMSConfig.fromEnvironment());
        }
        return client;
    }

    private static final class KeyWrapService extends Provider.Service {
        KeyWrapService(VectaKMSProvider provider) {
            super(provider, "Cipher", KEY_WRAP, VectaKeyWrapCipherSpi.class.getName(), null, null);
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            try {
                return new VectaKeyWrapCipherSpi(((VectaKMSProvider) getProvider()).client());
            } catch (RuntimeException e) {
                throw new NoSuchAlgorithmException("Vecta KMS provider is not configured: " + e.getMessage(), e);
            }
        }
    }
}
