package flowerwrong.github.com.smart.tunnel.shadowsocks.crypto;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import flowerwrong.github.com.smart.tcpip.IPHeader;
import flowerwrong.github.com.smart.tunnel.shadowsocks.ShadowSocksKey;
import flowerwrong.github.com.smart.util.CryptUtil;

/**
 * https://github.com/shadowsocks/shadowsocks-libev/blob/master/src/aead.c
 * https://shadowsocks.org/en/spec/AEAD-Ciphers.html
 * https://github.com/blinksocks/blinksocks/blob/master/src/presets/ss-aead-cipher.js
 */
public abstract class CryptAeadBase implements ICrypt {

    protected abstract AEADBlockCipher getCipher(boolean isEncrypted) throws InvalidAlgorithmParameterException;

    protected abstract void _encrypt(byte[] data, ByteArrayOutputStream stream);

    protected abstract void _decrypt(byte[] data, ByteArrayOutputStream stream);

    protected final byte[] info = "ss-subkey".getBytes();
    protected final int MAX_CHUNK_SPLIT_LEN = 0x3FFF;

    protected final String _name;
    protected final int _keyLength;
    protected final int _NonceLength;
    protected final int _TagLength;
    protected final ShadowSocksKey _ssKey;
    protected final int _protocol;

    protected byte[] encSubkey;
    protected byte[] decSubkey;
    protected byte[] encNonce;
    protected byte[] decNonce;

    protected AEADBlockCipher encCipher;
    protected AEADBlockCipher decCipher;

    protected final Lock encLock = new ReentrantLock();
    protected final Lock decLock = new ReentrantLock();

    public CryptAeadBase(String name, String password) {
        _name = name.toLowerCase();
        _keyLength = getKeyLength();
        _ssKey = new ShadowSocksKey(password, _keyLength);
        _NonceLength = 0;
        _TagLength = 0;
        _protocol = IPHeader.TCP; // TODO udp

        encNonce = new byte[getNonceLength()];
        decNonce = new byte[getNonceLength()];
    }

    protected CipherParameters getCipherParameters(boolean forEncryption) {
        byte[] nonce;
        if (_protocol == IPHeader.UDP) {
            nonce = forEncryption ? Arrays.copyOf(encNonce, getNonceLength()) : Arrays.copyOf(decNonce, getNonceLength());
        } else {
            nonce = new byte[getNonceLength()];
        }
        return new AEADParameters(
                new KeyParameter(forEncryption ? encSubkey : decSubkey),
                getTagLength() * 8,
                nonce
        );
    }

    @Override
    public byte[] encrypt(byte[] data) {
        byte[] salt = CryptUtil.randomBytes(getKeyLength());
        if (encSubkey == null) {
            encSubkey = CryptUtil.generateSubkey(_ssKey.getEncoded(), salt, info, getKeyLength());
        }

        int dataLen = data.length;

        CryptUtil.increment(encNonce);
        return new byte[0];
    }

    @Override
    public byte[] decrypt(byte[] data) {
        return new byte[0];
    }

    @Override
    public void encrypt(byte[] data, ByteArrayOutputStream stream) {

    }

    @Override
    public void encrypt(byte[] data, int length, ByteArrayOutputStream stream) {

    }

    @Override
    public void decrypt(byte[] data, ByteArrayOutputStream stream) {

    }

    @Override
    public void decrypt(byte[] data, int length, ByteArrayOutputStream stream) {

    }

    @Override
    public int getIVLength() {
        return 0;
    }

    @Override
    public int getKeyLength() {
        return 0;
    }

    public int getNonceLength() {
        return 0;
    }

    public int getTagLength() {
        return 0;
    }
}
