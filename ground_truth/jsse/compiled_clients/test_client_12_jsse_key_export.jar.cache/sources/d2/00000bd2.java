package org.bouncycastle.jce.provider;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/provider/BrokenKDF2BytesGenerator.class */
public class BrokenKDF2BytesGenerator implements DerivationFunction {
    private Digest digest;
    private byte[] shared;

    /* renamed from: iv */
    private byte[] f627iv;

    public BrokenKDF2BytesGenerator(Digest digest) {
        this.digest = digest;
    }

    @Override // org.bouncycastle.crypto.DerivationFunction
    public void init(DerivationParameters derivationParameters) {
        if (!(derivationParameters instanceof KDFParameters)) {
            throw new IllegalArgumentException("KDF parameters required for generator");
        }
        KDFParameters kDFParameters = (KDFParameters) derivationParameters;
        this.shared = kDFParameters.getSharedSecret();
        this.f627iv = kDFParameters.getIV();
    }

    public Digest getDigest() {
        return this.digest;
    }

    @Override // org.bouncycastle.crypto.DerivationFunction
    public int generateBytes(byte[] bArr, int i, int i2) throws DataLengthException, IllegalArgumentException {
        if (bArr.length - i2 < i) {
            throw new OutputLengthException("output buffer too small");
        }
        long j = i2 * 8;
        if (j > this.digest.getDigestSize() * 8 * 2147483648L) {
            throw new IllegalArgumentException("Output length too large");
        }
        int digestSize = (int) (j / this.digest.getDigestSize());
        byte[] bArr2 = new byte[this.digest.getDigestSize()];
        for (int i3 = 1; i3 <= digestSize; i3++) {
            this.digest.update(this.shared, 0, this.shared.length);
            this.digest.update((byte) (i3 & GF2Field.MASK));
            this.digest.update((byte) ((i3 >> 8) & GF2Field.MASK));
            this.digest.update((byte) ((i3 >> 16) & GF2Field.MASK));
            this.digest.update((byte) ((i3 >> 24) & GF2Field.MASK));
            this.digest.update(this.f627iv, 0, this.f627iv.length);
            this.digest.doFinal(bArr2, 0);
            if (i2 - i > bArr2.length) {
                System.arraycopy(bArr2, 0, bArr, i, bArr2.length);
                i += bArr2.length;
            } else {
                System.arraycopy(bArr2, 0, bArr, i, i2 - i);
            }
        }
        this.digest.reset();
        return i2;
    }
}