package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.impl.AbstractTlsSecret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class JceTlsSecret extends AbstractTlsSecret {
    private static final byte[] SSL3_CONST = generateSSL3Constants();
    protected final JcaTlsCrypto crypto;

    public JceTlsSecret(JcaTlsCrypto jcaTlsCrypto, byte[] bArr) {
        super(bArr);
        this.crypto = jcaTlsCrypto;
    }

    public static JceTlsSecret convert(JcaTlsCrypto jcaTlsCrypto, TlsSecret tlsSecret) {
        if (tlsSecret instanceof JceTlsSecret) {
            return (JceTlsSecret) tlsSecret;
        }
        if (tlsSecret instanceof AbstractTlsSecret) {
            return jcaTlsCrypto.adoptLocalSecret(copyData((AbstractTlsSecret) tlsSecret));
        }
        throw new IllegalArgumentException("unrecognized TlsSecret - cannot copy data: " + tlsSecret.getClass().getName());
    }

    private static byte[] generateSSL3Constants() {
        byte[] bArr = new byte[120];
        int i = 0;
        for (int i2 = 0; i2 < 15; i2++) {
            byte b = (byte) (i2 + 65);
            int i3 = 0;
            while (i3 <= i2) {
                bArr[i] = b;
                i3++;
                i++;
            }
        }
        return bArr;
    }

    @Override // org.bouncycastle.tls.crypto.TlsSecret
    public synchronized TlsSecret deriveUsingPRF(int i, String str, byte[] bArr, int i2) {
        checkAlive();
        try {
            if (i == 4) {
                return TlsCryptoUtils.hkdfExpandLabel(this, 4, str, bArr, i2);
            } else if (i == 5) {
                return TlsCryptoUtils.hkdfExpandLabel(this, 5, str, bArr, i2);
            } else if (i != 7) {
                return this.crypto.adoptLocalSecret(prf(i, str, bArr, i2));
            } else {
                return TlsCryptoUtils.hkdfExpandLabel(this, 7, str, bArr, i2);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override // org.bouncycastle.tls.crypto.impl.AbstractTlsSecret
    protected AbstractTlsCrypto getCrypto() {
        return this.crypto;
    }

    @Override // org.bouncycastle.tls.crypto.TlsSecret
    public synchronized TlsSecret hkdfExpand(int i, byte[] bArr, int i2) {
        if (i2 < 1) {
            return this.crypto.adoptLocalSecret(TlsUtils.EMPTY_BYTES);
        }
        int hashOutputSize = TlsCryptoUtils.getHashOutputSize(i);
        if (i2 > hashOutputSize * 255) {
            throw new IllegalArgumentException("'length' must be <= 255 * (output size of 'hashAlgorithm')");
        }
        checkAlive();
        byte[] bArr2 = this.data;
        try {
            String hMACAlgorithmName = this.crypto.getHMACAlgorithmName(i);
            Mac createMac = this.crypto.getHelper().createMac(hMACAlgorithmName);
            createMac.init(new SecretKeySpec(bArr2, 0, bArr2.length, hMACAlgorithmName));
            byte[] bArr3 = new byte[i2];
            byte[] bArr4 = new byte[hashOutputSize];
            byte b = 0;
            int i3 = 0;
            while (true) {
                createMac.update(bArr, 0, bArr.length);
                b = (byte) (b + 1);
                createMac.update(b);
                createMac.doFinal(bArr4, 0);
                int i4 = i2 - i3;
                if (i4 <= hashOutputSize) {
                    System.arraycopy(bArr4, 0, bArr3, i3, i4);
                    return this.crypto.adoptLocalSecret(bArr3);
                }
                System.arraycopy(bArr4, 0, bArr3, i3, hashOutputSize);
                i3 += hashOutputSize;
                createMac.update(bArr4, 0, hashOutputSize);
            }
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsSecret
    public synchronized TlsSecret hkdfExtract(int i, TlsSecret tlsSecret) {
        Mac createMac;
        checkAlive();
        byte[] bArr = this.data;
        this.data = null;
        try {
            String hMACAlgorithmName = this.crypto.getHMACAlgorithmName(i);
            createMac = this.crypto.getHelper().createMac(hMACAlgorithmName);
            createMac.init(new SecretKeySpec(bArr, 0, bArr.length, hMACAlgorithmName));
            convert(this.crypto, tlsSecret).updateMac(createMac);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
        return this.crypto.adoptLocalSecret(createMac.doFinal());
    }

    protected void hmacHash(int i, byte[] bArr, int i2, int i3, byte[] bArr2, byte[] bArr3) throws GeneralSecurityException {
        String str = "Hmac" + this.crypto.getDigestName(i).replaceAll("-", "");
        Mac createMac = this.crypto.getHelper().createMac(str);
        createMac.init(new SecretKeySpec(bArr, i2, i3, str));
        int macLength = createMac.getMacLength();
        byte[] bArr4 = new byte[macLength];
        byte[] bArr5 = new byte[macLength];
        int i4 = 0;
        byte[] bArr6 = bArr2;
        while (i4 < bArr3.length) {
            createMac.update(bArr6, 0, bArr6.length);
            createMac.doFinal(bArr4, 0);
            createMac.update(bArr4, 0, macLength);
            createMac.update(bArr2, 0, bArr2.length);
            createMac.doFinal(bArr5, 0);
            System.arraycopy(bArr5, 0, bArr3, i4, Math.min(macLength, bArr3.length - i4));
            i4 += macLength;
            bArr6 = bArr4;
        }
    }

    protected byte[] prf(int i, String str, byte[] bArr, int i2) throws GeneralSecurityException {
        if (i == 0) {
            return prf_SSL(bArr, i2);
        }
        byte[] concatenate = Arrays.concatenate(Strings.toByteArray(str), bArr);
        return 1 == i ? prf_1_0(concatenate, i2) : prf_1_2(i, concatenate, i2);
    }

    protected byte[] prf_1_0(byte[] bArr, int i) throws GeneralSecurityException {
        int length = (this.data.length + 1) / 2;
        byte[] bArr2 = new byte[i];
        hmacHash(1, this.data, 0, length, bArr, bArr2);
        byte[] bArr3 = new byte[i];
        hmacHash(2, this.data, this.data.length - length, length, bArr, bArr3);
        for (int i2 = 0; i2 < i; i2++) {
            bArr2[i2] = (byte) (bArr2[i2] ^ bArr3[i2]);
        }
        return bArr2;
    }

    protected byte[] prf_1_2(int i, byte[] bArr, int i2) throws GeneralSecurityException {
        int hashForPRF = TlsCryptoUtils.getHashForPRF(i);
        byte[] bArr2 = new byte[i2];
        hmacHash(hashForPRF, this.data, 0, this.data.length, bArr, bArr2);
        return bArr2;
    }

    protected byte[] prf_SSL(byte[] bArr, int i) throws GeneralSecurityException {
        MessageDigest createMessageDigest = this.crypto.getHelper().createMessageDigest("MD5");
        MessageDigest createMessageDigest2 = this.crypto.getHelper().createMessageDigest(McElieceCCA2KeyGenParameterSpec.SHA1);
        int digestLength = createMessageDigest.getDigestLength();
        int digestLength2 = createMessageDigest2.getDigestLength();
        byte[] bArr2 = new byte[Math.max(digestLength, digestLength2)];
        byte[] bArr3 = new byte[i];
        int i2 = 1;
        int i3 = 0;
        int i4 = 0;
        while (i3 < i) {
            createMessageDigest2.update(SSL3_CONST, i4, i2);
            int i5 = i2 + 1;
            i4 += i2;
            createMessageDigest2.update(this.data, 0, this.data.length);
            createMessageDigest2.update(bArr, 0, bArr.length);
            createMessageDigest2.digest(bArr2, 0, digestLength2);
            createMessageDigest.update(this.data, 0, this.data.length);
            createMessageDigest.update(bArr2, 0, digestLength2);
            int i6 = i - i3;
            if (i6 < digestLength) {
                createMessageDigest.digest(bArr2, 0, digestLength);
                System.arraycopy(bArr2, 0, bArr3, i3, i6);
                i3 += i6;
            } else {
                createMessageDigest.digest(bArr3, i3, digestLength);
                i3 += digestLength;
            }
            i2 = i5;
        }
        return bArr3;
    }

    protected synchronized void updateMac(Mac mac) {
        checkAlive();
        mac.update(this.data, 0, this.data.length);
    }
}