package flowerwrong.github.com.smart.util;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.security.SecureRandom;

public final class CryptUtil {

    private CryptUtil() {
        throw new UnsupportedOperationException("u can't instantiate me...");
    }

    public static byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    public static byte[] generateSubkey(byte[] ikm, byte[] salt, byte[] info, int keyLen) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA1Digest());
        hkdf.init(new HKDFParameters(ikm, salt, info));
        byte[] okm = new byte[keyLen];
        hkdf.generateBytes(okm, 0, keyLen);
        return okm;
    }

    public static void increment(byte[] nonce) {
        for (int i = 0; i < nonce.length; i++) {
            ++nonce[i];
            if (nonce[i] != 0) {
                break;
            }
        }
    }
}
