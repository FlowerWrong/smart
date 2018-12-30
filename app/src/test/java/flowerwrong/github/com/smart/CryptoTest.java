package flowerwrong.github.com.smart;

import org.junit.Assert;
import org.junit.Test;

import java.util.List;

import flowerwrong.github.com.smart.tunnel.shadowsocks.crypto.CryptFactory;


/**
 * https://github.com/shadowsocks/shadowsocks-libev/blob/master/src/stream.c#L75-L96
 * https://github.com/shadowsocks/shadowsocks-libev/blob/master/src/aead.c#L43-L56
 * Encrypt method: 26
 * rc4-md5,
 * aes-128-gcm, aes-192-gcm, aes-256-gcm,
 * aes-128-cfb, aes-192-cfb, aes-256-cfb,
 * aes-128-ctr, aes-192-ctr, aes-256-ctr,
 * camellia-128-cfb, camellia-192-cfb,
 * camellia-256-cfb, bf-cfb,
 * chacha20-ietf-poly1305,
 * xchacha20-ietf-poly1305,
 * salsa20, chacha20 and chacha20-ietf.
 * The default cipher is chacha20-ietf-poly1305.
 */
public class CryptoTest {
    @Test
    public void testSupportedCiphers() {
        List<String> scs = CryptFactory.getSupportedCiphers();
        System.out.println(scs);
        Assert.assertEquals(14, scs.size());
    }
}
