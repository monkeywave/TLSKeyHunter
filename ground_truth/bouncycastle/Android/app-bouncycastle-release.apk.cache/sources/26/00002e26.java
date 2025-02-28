package org.bouncycastle.tls.crypto.impl.p018bc;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.impl.AbstractTlsSecret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsSecret */
/* loaded from: classes2.dex */
public class BcTlsSecret extends AbstractTlsSecret {
    private static final byte[] SSL3_CONST = generateSSL3Constants();
    protected final BcTlsCrypto crypto;

    public BcTlsSecret(BcTlsCrypto bcTlsCrypto, byte[] bArr) {
        super(bArr);
        this.crypto = bcTlsCrypto;
    }

    public static BcTlsSecret convert(BcTlsCrypto bcTlsCrypto, TlsSecret tlsSecret) {
        if (tlsSecret instanceof BcTlsSecret) {
            return (BcTlsSecret) tlsSecret;
        }
        if (tlsSecret instanceof AbstractTlsSecret) {
            return bcTlsCrypto.adoptLocalSecret(copyData((AbstractTlsSecret) tlsSecret));
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
        HMac hMac = new HMac(this.crypto.createDigest(i));
        hMac.init(new KeyParameter(bArr2));
        byte[] bArr3 = new byte[i2];
        byte[] bArr4 = new byte[hashOutputSize];
        byte b = 0;
        int i3 = 0;
        while (true) {
            hMac.update(bArr, 0, bArr.length);
            b = (byte) (b + 1);
            hMac.update(b);
            hMac.doFinal(bArr4, 0);
            int i4 = i2 - i3;
            if (i4 <= hashOutputSize) {
                System.arraycopy(bArr4, 0, bArr3, i3, i4);
                return this.crypto.adoptLocalSecret(bArr3);
            }
            System.arraycopy(bArr4, 0, bArr3, i3, hashOutputSize);
            i3 += hashOutputSize;
            hMac.update(bArr4, 0, hashOutputSize);
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsSecret
    public synchronized TlsSecret hkdfExtract(int i, TlsSecret tlsSecret) {
        byte[] bArr;
        checkAlive();
        byte[] bArr2 = this.data;
        this.data = null;
        HMac hMac = new HMac(this.crypto.createDigest(i));
        hMac.init(new KeyParameter(bArr2));
        convert(this.crypto, tlsSecret).updateMac(hMac);
        bArr = new byte[hMac.getMacSize()];
        hMac.doFinal(bArr, 0);
        return this.crypto.adoptLocalSecret(bArr);
    }

    protected void hmacHash(int i, byte[] bArr, int i2, int i3, byte[] bArr2, byte[] bArr3) {
        HMac hMac = new HMac(this.crypto.createDigest(i));
        hMac.init(new KeyParameter(bArr, i2, i3));
        int macSize = hMac.getMacSize();
        byte[] bArr4 = new byte[macSize];
        byte[] bArr5 = new byte[macSize];
        int i4 = 0;
        byte[] bArr6 = bArr2;
        while (i4 < bArr3.length) {
            hMac.update(bArr6, 0, bArr6.length);
            hMac.doFinal(bArr4, 0);
            hMac.update(bArr4, 0, macSize);
            hMac.update(bArr2, 0, bArr2.length);
            hMac.doFinal(bArr5, 0);
            System.arraycopy(bArr5, 0, bArr3, i4, Math.min(macSize, bArr3.length - i4));
            i4 += macSize;
            bArr6 = bArr4;
        }
    }

    protected byte[] prf(int i, String str, byte[] bArr, int i2) {
        if (i == 0) {
            return prf_SSL(bArr, i2);
        }
        byte[] concatenate = Arrays.concatenate(Strings.toByteArray(str), bArr);
        return 1 == i ? prf_1_0(concatenate, i2) : prf_1_2(i, concatenate, i2);
    }

    protected byte[] prf_1_0(byte[] bArr, int i) {
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

    protected byte[] prf_1_2(int i, byte[] bArr, int i2) {
        int hashForPRF = TlsCryptoUtils.getHashForPRF(i);
        byte[] bArr2 = new byte[i2];
        hmacHash(hashForPRF, this.data, 0, this.data.length, bArr, bArr2);
        return bArr2;
    }

    protected byte[] prf_SSL(byte[] bArr, int i) {
        int i2 = 1;
        Digest createDigest = this.crypto.createDigest(1);
        Digest createDigest2 = this.crypto.createDigest(2);
        int digestSize = createDigest.getDigestSize();
        int digestSize2 = createDigest2.getDigestSize();
        byte[] bArr2 = new byte[Math.max(digestSize, digestSize2)];
        byte[] bArr3 = new byte[i];
        int i3 = 0;
        int i4 = 0;
        while (i3 < i) {
            createDigest2.update(SSL3_CONST, i4, i2);
            int i5 = i2 + 1;
            i4 += i2;
            createDigest2.update(this.data, 0, this.data.length);
            createDigest2.update(bArr, 0, bArr.length);
            createDigest2.doFinal(bArr2, 0);
            createDigest.update(this.data, 0, this.data.length);
            createDigest.update(bArr2, 0, digestSize2);
            int i6 = i - i3;
            if (i6 < digestSize) {
                createDigest.doFinal(bArr2, 0);
                System.arraycopy(bArr2, 0, bArr3, i3, i6);
                i3 += i6;
            } else {
                createDigest.doFinal(bArr3, i3);
                i3 += digestSize;
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