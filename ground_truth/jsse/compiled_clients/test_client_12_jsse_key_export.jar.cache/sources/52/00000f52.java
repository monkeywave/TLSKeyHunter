package org.openjsse.com.sun.crypto.provider;

import java.io.UnsupportedEncodingException;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.openjsse.sun.security.internal.spec.TlsPrfParameterSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/TlsPrfGenerator.class */
abstract class TlsPrfGenerator extends KeyGeneratorSpi {

    /* renamed from: B0 */
    private static final byte[] f954B0 = new byte[0];
    static final byte[] LABEL_MASTER_SECRET = {109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116};
    static final byte[] LABEL_EXTENDED_MASTER_SECRET = {101, 120, 116, 101, 110, 100, 101, 100, 32, 109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116};
    static final byte[] LABEL_KEY_EXPANSION = {107, 101, 121, 32, 101, 120, 112, 97, 110, 115, 105, 111, 110};
    static final byte[] LABEL_CLIENT_WRITE_KEY = {99, 108, 105, 101, 110, 116, 32, 119, 114, 105, 116, 101, 32, 107, 101, 121};
    static final byte[] LABEL_SERVER_WRITE_KEY = {115, 101, 114, 118, 101, 114, 32, 119, 114, 105, 116, 101, 32, 107, 101, 121};
    static final byte[] LABEL_IV_BLOCK = {73, 86, 32, 98, 108, 111, 99, 107};
    private static final byte[] HMAC_ipad64 = genPad((byte) 54, 64);
    private static final byte[] HMAC_ipad128 = genPad((byte) 54, 128);
    private static final byte[] HMAC_opad64 = genPad((byte) 92, 64);
    private static final byte[] HMAC_opad128 = genPad((byte) 92, 128);
    static final byte[][] SSL3_CONST = genConst();
    private static final String MSG = "TlsPrfGenerator must be initialized using a TlsPrfParameterSpec";
    private TlsPrfParameterSpec spec;

    static byte[] genPad(byte b, int count) {
        byte[] padding = new byte[count];
        Arrays.fill(padding, b);
        return padding;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] concat(byte[] b1, byte[] b2) {
        int n1 = b1.length;
        int n2 = b2.length;
        byte[] b = new byte[n1 + n2];
        System.arraycopy(b1, 0, b, 0, n1);
        System.arraycopy(b2, 0, b, n1, n2);
        return b;
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [byte[], byte[][]] */
    private static byte[][] genConst() {
        ?? r0 = new byte[10];
        for (int i = 0; i < 10; i++) {
            byte[] b = new byte[i + 1];
            Arrays.fill(b, (byte) (65 + i));
            r0[i] = b;
        }
        return r0;
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected void engineInit(SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (!(params instanceof TlsPrfParameterSpec)) {
            throw new InvalidAlgorithmParameterException(MSG);
        }
        this.spec = (TlsPrfParameterSpec) params;
        SecretKey key = this.spec.getSecret();
        if (key != null && !"RAW".equals(key.getFormat())) {
            throw new InvalidAlgorithmParameterException("Key encoding format must be RAW");
        }
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected void engineInit(int keysize, SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    SecretKey engineGenerateKey0(boolean tls12) {
        byte[] doTLS10PRF;
        if (this.spec == null) {
            throw new IllegalStateException("TlsPrfGenerator must be initialized");
        }
        SecretKey key = this.spec.getSecret();
        byte[] secret = key == null ? null : key.getEncoded();
        try {
            byte[] labelBytes = this.spec.getLabel().getBytes("UTF8");
            int n = this.spec.getOutputLength();
            if (tls12) {
                doTLS10PRF = doTLS12PRF(secret, labelBytes, this.spec.getSeed(), n, this.spec.getPRFHashAlg(), this.spec.getPRFHashLength(), this.spec.getPRFBlockSize());
            } else {
                doTLS10PRF = doTLS10PRF(secret, labelBytes, this.spec.getSeed(), n);
            }
            byte[] prfBytes = doTLS10PRF;
            return new SecretKeySpec(prfBytes, "TlsPrf");
        } catch (UnsupportedEncodingException e) {
            throw new ProviderException("Could not generate PRF", e);
        } catch (GeneralSecurityException e2) {
            throw new ProviderException("Could not generate PRF", e2);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] doTLS12PRF(byte[] secret, byte[] labelBytes, byte[] seed, int outputLength, String prfHash, int prfHashLength, int prfBlockSize) throws NoSuchAlgorithmException, DigestException {
        if (prfHash == null) {
            throw new NoSuchAlgorithmException("Unspecified PRF algorithm");
        }
        MessageDigest prfMD = MessageDigest.getInstance(prfHash);
        return doTLS12PRF(secret, labelBytes, seed, outputLength, prfMD, prfHashLength, prfBlockSize);
    }

    static byte[] doTLS12PRF(byte[] secret, byte[] labelBytes, byte[] seed, int outputLength, MessageDigest mdPRF, int mdPRFLen, int mdPRFBlockSize) throws DigestException {
        byte[] ipad;
        byte[] opad;
        if (secret == null) {
            secret = f954B0;
        }
        if (secret.length > mdPRFBlockSize) {
            secret = mdPRF.digest(secret);
        }
        byte[] output = new byte[outputLength];
        switch (mdPRFBlockSize) {
            case 64:
                ipad = (byte[]) HMAC_ipad64.clone();
                opad = (byte[]) HMAC_opad64.clone();
                break;
            case 128:
                ipad = (byte[]) HMAC_ipad128.clone();
                opad = (byte[]) HMAC_opad128.clone();
                break;
            default:
                throw new DigestException("Unexpected block size.");
        }
        expand(mdPRF, mdPRFLen, secret, 0, secret.length, labelBytes, seed, output, ipad, opad);
        return output;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] doTLS10PRF(byte[] secret, byte[] labelBytes, byte[] seed, int outputLength) throws NoSuchAlgorithmException, DigestException {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha = MessageDigest.getInstance("SHA1");
        return doTLS10PRF(secret, labelBytes, seed, outputLength, md5, sha);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] doTLS10PRF(byte[] secret, byte[] labelBytes, byte[] seed, int outputLength, MessageDigest md5, MessageDigest sha) throws DigestException {
        if (secret == null) {
            secret = f954B0;
        }
        int off = secret.length >> 1;
        int seclen = off + (secret.length & 1);
        byte[] secKey = secret;
        int keyLen = seclen;
        byte[] output = new byte[outputLength];
        if (seclen > 64) {
            md5.update(secret, 0, seclen);
            secKey = md5.digest();
            keyLen = secKey.length;
        }
        expand(md5, 16, secKey, 0, keyLen, labelBytes, seed, output, (byte[]) HMAC_ipad64.clone(), (byte[]) HMAC_opad64.clone());
        if (seclen > 64) {
            sha.update(secret, off, seclen);
            secKey = sha.digest();
            keyLen = secKey.length;
            off = 0;
        }
        expand(sha, 20, secKey, off, keyLen, labelBytes, seed, output, (byte[]) HMAC_ipad64.clone(), (byte[]) HMAC_opad64.clone());
        return output;
    }

    private static void expand(MessageDigest digest, int hmacSize, byte[] secret, int secOff, int secLen, byte[] label, byte[] seed, byte[] output, byte[] pad1, byte[] pad2) throws DigestException {
        for (int i = 0; i < secLen; i++) {
            int i2 = i;
            pad1[i2] = (byte) (pad1[i2] ^ secret[i + secOff]);
            int i3 = i;
            pad2[i3] = (byte) (pad2[i3] ^ secret[i + secOff]);
        }
        byte[] tmp = new byte[hmacSize];
        byte[] aBytes = null;
        int remaining = output.length;
        int ofs = 0;
        while (remaining > 0) {
            digest.update(pad1);
            if (aBytes == null) {
                digest.update(label);
                digest.update(seed);
            } else {
                digest.update(aBytes);
            }
            digest.digest(tmp, 0, hmacSize);
            digest.update(pad2);
            digest.update(tmp);
            if (aBytes == null) {
                aBytes = new byte[hmacSize];
            }
            digest.digest(aBytes, 0, hmacSize);
            digest.update(pad1);
            digest.update(aBytes);
            digest.update(label);
            digest.update(seed);
            digest.digest(tmp, 0, hmacSize);
            digest.update(pad2);
            digest.update(tmp);
            digest.digest(tmp, 0, hmacSize);
            int k = Math.min(hmacSize, remaining);
            for (int i4 = 0; i4 < k; i4++) {
                int i5 = ofs;
                ofs++;
                output[i5] = (byte) (output[i5] ^ tmp[i4]);
            }
            remaining -= k;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/TlsPrfGenerator$V12.class */
    public static class V12 extends TlsPrfGenerator {
        @Override // javax.crypto.KeyGeneratorSpi
        protected SecretKey engineGenerateKey() {
            return engineGenerateKey0(true);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/TlsPrfGenerator$V10.class */
    public static class V10 extends TlsPrfGenerator {
        @Override // javax.crypto.KeyGeneratorSpi
        protected SecretKey engineGenerateKey() {
            return engineGenerateKey0(false);
        }
    }
}