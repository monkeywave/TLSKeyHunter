package org.bouncycastle.crypto.agreement.kdf;

import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.KDFParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/agreement/kdf/ConcatenationKDFGenerator.class */
public class ConcatenationKDFGenerator implements DerivationFunction {
    private Digest digest;
    private byte[] shared;
    private byte[] otherInfo;
    private int hLen;

    public ConcatenationKDFGenerator(Digest digest) {
        this.digest = digest;
        this.hLen = digest.getDigestSize();
    }

    @Override // org.bouncycastle.crypto.DerivationFunction
    public void init(DerivationParameters derivationParameters) {
        if (!(derivationParameters instanceof KDFParameters)) {
            throw new IllegalArgumentException("KDF parameters required for generator");
        }
        KDFParameters kDFParameters = (KDFParameters) derivationParameters;
        this.shared = kDFParameters.getSharedSecret();
        this.otherInfo = kDFParameters.getIV();
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

    /* JADX WARN: Removed duplicated region for block: B:12:0x00ac  */
    @Override // org.bouncycastle.crypto.DerivationFunction
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public int generateBytes(byte[] r8, int r9, int r10) throws org.bouncycastle.crypto.DataLengthException, java.lang.IllegalArgumentException {
        /*
            Method dump skipped, instructions count: 263
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator.generateBytes(byte[], int, int):int");
    }
}