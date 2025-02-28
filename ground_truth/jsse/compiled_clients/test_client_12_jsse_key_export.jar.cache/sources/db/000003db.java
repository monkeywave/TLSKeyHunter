package org.bouncycastle.crypto.agreement.kdf;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.DigestDerivationFunction;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/agreement/kdf/GSKKFDGenerator.class */
public class GSKKFDGenerator implements DigestDerivationFunction {
    private final Digest digest;

    /* renamed from: z */
    private byte[] f107z;
    private int counter;

    /* renamed from: r */
    private byte[] f108r;
    private byte[] buf;

    public GSKKFDGenerator(Digest digest) {
        this.digest = digest;
        this.buf = new byte[digest.getDigestSize()];
    }

    @Override // org.bouncycastle.crypto.DigestDerivationFunction
    public Digest getDigest() {
        return this.digest;
    }

    @Override // org.bouncycastle.crypto.DerivationFunction
    public void init(DerivationParameters derivationParameters) {
        if (!(derivationParameters instanceof GSKKDFParameters)) {
            throw new IllegalArgumentException("unkown parameters type");
        }
        this.f107z = ((GSKKDFParameters) derivationParameters).getZ();
        this.counter = ((GSKKDFParameters) derivationParameters).getStartCounter();
        this.f108r = ((GSKKDFParameters) derivationParameters).getNonce();
    }

    @Override // org.bouncycastle.crypto.DerivationFunction
    public int generateBytes(byte[] bArr, int i, int i2) throws DataLengthException, IllegalArgumentException {
        if (i + i2 > bArr.length) {
            throw new DataLengthException("output buffer too small");
        }
        this.digest.update(this.f107z, 0, this.f107z.length);
        int i3 = this.counter;
        this.counter = i3 + 1;
        byte[] intToBigEndian = Pack.intToBigEndian(i3);
        this.digest.update(intToBigEndian, 0, intToBigEndian.length);
        if (this.f108r != null) {
            this.digest.update(this.f108r, 0, this.f108r.length);
        }
        this.digest.doFinal(this.buf, 0);
        System.arraycopy(this.buf, 0, bArr, i, i2);
        Arrays.clear(this.buf);
        return i2;
    }
}