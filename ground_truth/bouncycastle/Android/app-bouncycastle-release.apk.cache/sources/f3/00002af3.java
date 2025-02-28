package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public final class KeyedHashFunctions {
    private final Digest digest;
    private final int digestSize;

    /* JADX INFO: Access modifiers changed from: protected */
    public KeyedHashFunctions(ASN1ObjectIdentifier aSN1ObjectIdentifier, int i) {
        if (aSN1ObjectIdentifier == null) {
            throw new NullPointerException("digest == null");
        }
        this.digest = DigestUtil.getDigest(aSN1ObjectIdentifier);
        this.digestSize = i;
    }

    private byte[] coreDigest(int i, byte[] bArr, byte[] bArr2) {
        byte[] bytesBigEndian = XMSSUtil.toBytesBigEndian(i, this.digestSize);
        this.digest.update(bytesBigEndian, 0, bytesBigEndian.length);
        this.digest.update(bArr, 0, bArr.length);
        this.digest.update(bArr2, 0, bArr2.length);
        int i2 = this.digestSize;
        byte[] bArr3 = new byte[i2];
        Digest digest = this.digest;
        if (digest instanceof Xof) {
            ((Xof) digest).doFinal(bArr3, 0, i2);
        } else {
            digest.doFinal(bArr3, 0);
        }
        return bArr3;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* renamed from: F */
    public byte[] m11F(byte[] bArr, byte[] bArr2) {
        int length = bArr.length;
        int i = this.digestSize;
        if (length == i) {
            if (bArr2.length == i) {
                return coreDigest(0, bArr, bArr2);
            }
            throw new IllegalArgumentException("wrong in length");
        }
        throw new IllegalArgumentException("wrong key length");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* renamed from: H */
    public byte[] m10H(byte[] bArr, byte[] bArr2) {
        int length = bArr.length;
        int i = this.digestSize;
        if (length == i) {
            if (bArr2.length == i * 2) {
                return coreDigest(1, bArr, bArr2);
            }
            throw new IllegalArgumentException("wrong in length");
        }
        throw new IllegalArgumentException("wrong key length");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public byte[] HMsg(byte[] bArr, byte[] bArr2) {
        if (bArr.length == this.digestSize * 3) {
            return coreDigest(2, bArr, bArr2);
        }
        throw new IllegalArgumentException("wrong key length");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public byte[] PRF(byte[] bArr, byte[] bArr2) {
        if (bArr.length == this.digestSize) {
            if (bArr2.length == 32) {
                return coreDigest(3, bArr, bArr2);
            }
            throw new IllegalArgumentException("wrong address length");
        }
        throw new IllegalArgumentException("wrong key length");
    }
}