package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.MGFParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/generators/MGF1BytesGenerator.class */
public class MGF1BytesGenerator implements DerivationFunction {
    private Digest digest;
    private byte[] seed;
    private int hLen;

    public MGF1BytesGenerator(Digest digest) {
        this.digest = digest;
        this.hLen = digest.getDigestSize();
    }

    @Override // org.bouncycastle.crypto.DerivationFunction
    public void init(DerivationParameters derivationParameters) {
        if (!(derivationParameters instanceof MGFParameters)) {
            throw new IllegalArgumentException("MGF parameters required for MGF1Generator");
        }
        this.seed = ((MGFParameters) derivationParameters).getSeed();
    }

    public Digest getDigest() {
        return this.digest;
    }

    private void ItoOSP(int i, byte[] bArr) {
        bArr[0] = (byte) (i >>> 24);
        bArr[1] = (byte) (i >>> 16);
        bArr[2] = (byte) (i >>> 8);
        bArr[3] = (byte) (i >>> 0);
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0097  */
    @Override // org.bouncycastle.crypto.DerivationFunction
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public int generateBytes(byte[] r9, int r10, int r11) throws org.bouncycastle.crypto.DataLengthException, java.lang.IllegalArgumentException {
        /*
            Method dump skipped, instructions count: 233
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.crypto.generators.MGF1BytesGenerator.generateBytes(byte[], int, int):int");
    }
}