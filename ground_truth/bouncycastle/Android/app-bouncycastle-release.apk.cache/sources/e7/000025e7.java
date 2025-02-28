package org.bouncycastle.jce.provider;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KDFParameters;

/* loaded from: classes2.dex */
public class BrokenKDF2BytesGenerator implements DerivationFunction {
    private Digest digest;

    /* renamed from: iv */
    private byte[] f955iv;
    private byte[] shared;

    public BrokenKDF2BytesGenerator(Digest digest) {
        this.digest = digest;
    }

    @Override // org.bouncycastle.crypto.DerivationFunction
    public int generateBytes(byte[] bArr, int i, int i2) throws DataLengthException, IllegalArgumentException {
        if (bArr.length - i2 >= i) {
            long j = i2 * 8;
            if (j <= this.digest.getDigestSize() * 17179869184L) {
                int digestSize = (int) (j / this.digest.getDigestSize());
                int digestSize2 = this.digest.getDigestSize();
                byte[] bArr2 = new byte[digestSize2];
                for (int i3 = 1; i3 <= digestSize; i3++) {
                    Digest digest = this.digest;
                    byte[] bArr3 = this.shared;
                    digest.update(bArr3, 0, bArr3.length);
                    this.digest.update((byte) (i3 & 255));
                    this.digest.update((byte) ((i3 >> 8) & 255));
                    this.digest.update((byte) ((i3 >> 16) & 255));
                    this.digest.update((byte) ((i3 >> 24) & 255));
                    Digest digest2 = this.digest;
                    byte[] bArr4 = this.f955iv;
                    digest2.update(bArr4, 0, bArr4.length);
                    this.digest.doFinal(bArr2, 0);
                    int i4 = i2 - i;
                    if (i4 > digestSize2) {
                        System.arraycopy(bArr2, 0, bArr, i, digestSize2);
                        i += digestSize2;
                    } else {
                        System.arraycopy(bArr2, 0, bArr, i, i4);
                    }
                }
                this.digest.reset();
                return i2;
            }
            throw new IllegalArgumentException("Output length too large");
        }
        throw new OutputLengthException("output buffer too small");
    }

    public Digest getDigest() {
        return this.digest;
    }

    @Override // org.bouncycastle.crypto.DerivationFunction
    public void init(DerivationParameters derivationParameters) {
        if (!(derivationParameters instanceof KDFParameters)) {
            throw new IllegalArgumentException("KDF parameters required for generator");
        }
        KDFParameters kDFParameters = (KDFParameters) derivationParameters;
        this.shared = kDFParameters.getSharedSecret();
        this.f955iv = kDFParameters.getIV();
    }
}