package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/CSHAKEDigest.class */
public class CSHAKEDigest extends SHAKEDigest {
    private static final byte[] padding = new byte[100];
    private final byte[] diff;

    public CSHAKEDigest(int i, byte[] bArr, byte[] bArr2) {
        super(i);
        if ((bArr == null || bArr.length == 0) && (bArr2 == null || bArr2.length == 0)) {
            this.diff = null;
            return;
        }
        this.diff = Arrays.concatenate(XofUtils.leftEncode(this.rate / 8), encodeString(bArr), encodeString(bArr2));
        diffPadAndAbsorb();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CSHAKEDigest(CSHAKEDigest cSHAKEDigest) {
        super(cSHAKEDigest);
        this.diff = Arrays.clone(cSHAKEDigest.diff);
    }

    private void diffPadAndAbsorb() {
        int i = this.rate / 8;
        absorb(this.diff, 0, this.diff.length);
        int length = this.diff.length % i;
        if (length == 0) {
            return;
        }
        int i2 = i;
        int i3 = length;
        while (true) {
            int i4 = i2 - i3;
            if (i4 <= padding.length) {
                absorb(padding, 0, i4);
                return;
            }
            absorb(padding, 0, padding.length);
            i2 = i4;
            i3 = padding.length;
        }
    }

    private byte[] encodeString(byte[] bArr) {
        return (bArr == null || bArr.length == 0) ? XofUtils.leftEncode(0L) : Arrays.concatenate(XofUtils.leftEncode(bArr.length * 8), bArr);
    }

    @Override // org.bouncycastle.crypto.digests.SHAKEDigest, org.bouncycastle.crypto.digests.KeccakDigest, org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "CSHAKE" + this.fixedOutputLength;
    }

    @Override // org.bouncycastle.crypto.digests.SHAKEDigest, org.bouncycastle.crypto.Xof
    public int doOutput(byte[] bArr, int i, int i2) {
        if (this.diff != null) {
            if (!this.squeezing) {
                absorbBits(0, 2);
            }
            squeeze(bArr, i, i2 * 8);
            return i2;
        }
        return super.doOutput(bArr, i, i2);
    }

    @Override // org.bouncycastle.crypto.digests.KeccakDigest, org.bouncycastle.crypto.Digest
    public void reset() {
        super.reset();
        if (this.diff != null) {
            diffPadAndAbsorb();
        }
    }
}