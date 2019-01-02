package flowerwrong.github.com.smart.tunnel.shadowsocks.crypto;

import org.bouncycastle.crypto.modes.AEADBlockCipher;

import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.util.HashMap;
import java.util.Map;

public class AeadCrypt extends CryptAeadBase {

    public final static String CIPHER_AES_128_GCM = "aes-128-gcm";
    public final static String CIPHER_AES_192_GCM = "aes-192-gcm"; // TODO
    public final static String CIPHER_AES_256_GCM = "aes-256-gcm";
    public final static String CIPHER_CHACHA20_POLY1305 = "chacha20-ietf-poly1305";
    public final static String CIPHER_XCHACHA20_POLY1305 = "xchacha20-ietf-poly1305"; // TODO


    @Override
    protected AEADBlockCipher getCipher(boolean isEncrypted) throws InvalidAlgorithmParameterException {
        return null;
    }

    @Override
    protected void _encrypt(byte[] data, ByteArrayOutputStream stream) {

    }

    @Override
    protected void _decrypt(byte[] data, ByteArrayOutputStream stream) {

    }

    public AeadCrypt(String name, String password) {
        super(name, password);
    }

    public static Map<String, String> getCiphers() {
        Map<String, String> ciphers = new HashMap<String, String>();
        ciphers.put(CIPHER_AES_128_GCM, AeadCrypt.class.getName());
        ciphers.put(CIPHER_AES_256_GCM, AeadCrypt.class.getName());
        ciphers.put(CIPHER_CHACHA20_POLY1305, AeadCrypt.class.getName());
        return ciphers;
    }

    /**
     * salt len = key len
     */
    @Override
    public int getKeyLength() {
        if (_name.equals(CIPHER_AES_128_GCM)) {
            return 16;
        } else if (_name.equals(CIPHER_AES_192_GCM)) {
            return 24;
        }
        return 32;
    }

    @Override
    public int getNonceLength() {
        if (_name.equals(CIPHER_XCHACHA20_POLY1305)) {
            return 24;
        }
        return 12;
    }

    @Override
    public int getTagLength() {
        return 16;
    }
}
