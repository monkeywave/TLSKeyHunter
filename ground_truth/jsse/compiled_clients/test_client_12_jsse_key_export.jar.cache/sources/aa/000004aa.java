package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.DigestDerivationFunction;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.ISO18033KDFParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/generators/BaseKDFBytesGenerator.class */
public class BaseKDFBytesGenerator implements DigestDerivationFunction {
    private int counterStart;
    private Digest digest;
    private byte[] shared;

    /* renamed from: iv */
    private byte[] f400iv;

    /* JADX INFO: Access modifiers changed from: protected */
    public BaseKDFBytesGenerator(int i, Digest digest) {
        this.counterStart = i;
        this.digest = digest;
    }

    @Override // org.bouncycastle.crypto.DerivationFunction
    public void init(DerivationParameters derivationParameters) {
        if (derivationParameters instanceof KDFParameters) {
            KDFParameters kDFParameters = (KDFParameters) derivationParameters;
            this.shared = kDFParameters.getSharedSecret();
            this.f400iv = kDFParameters.getIV();
        } else if (!(derivationParameters instanceof ISO18033KDFParameters)) {
            throw new IllegalArgumentException("KDF parameters required for generator");
        } else {
            this.shared = ((ISO18033KDFParameters) derivationParameters).getSeed();
            this.f400iv = null;
        }
    }

    @Override // org.bouncycastle.crypto.DigestDerivationFunction
    public Digest getDigest() {
        return this.digest;
    }

    @Override // org.bouncycastle.crypto.DerivationFunction
    public int generateBytes(byte[] bArr, int i, int i2) throws DataLengthException, IllegalArgumentException {
        if (bArr.length - i2 < i) {
            throw new OutputLengthException("output buffer too small");
        }
        long j = i2;
        int digestSize = this.digest.getDigestSize();
        if (j > 8589934591L) {
            throw new IllegalArgumentException("Output length too large");
        }
        int i3 = (int) (((j + digestSize) - 1) / digestSize);
        byte[] bArr2 = new byte[this.digest.getDigestSize()];
        byte[] bArr3 = new byte[4];
        Pack.intToBigEndian(this.counterStart, bArr3, 0);
        int i4 = this.counterStart & (-256);
        for (int i5 = 0; i5 < i3; i5++) {
            this.digest.update(this.shared, 0, this.shared.length);
            this.digest.update(bArr3, 0, bArr3.length);
            if (this.f400iv != null) {
                this.digest.update(this.f400iv, 0, this.f400iv.length);
            }
            this.digest.doFinal(bArr2, 0);
            if (i2 > digestSize) {
                System.arraycopy(bArr2, 0, bArr, i, digestSize);
                i += digestSize;
                i2 -= digestSize;
            } else {
                System.arraycopy(bArr2, 0, bArr, i, i2);
            }
            byte b = (byte) (bArr3[3] + 1);
            bArr3[3] = b;
            if (b == 0) {
                i4 += 256;
                Pack.intToBigEndian(i4, bArr3, 0);
            }
        }
        this.digest.reset();
        return (int) j;
    }
}