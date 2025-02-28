package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/NullDigest.class */
public class NullDigest implements Digest {
    private OpenByteArrayOutputStream bOut = new OpenByteArrayOutputStream();

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/NullDigest$OpenByteArrayOutputStream.class */
    public static class OpenByteArrayOutputStream extends ByteArrayOutputStream {
        private OpenByteArrayOutputStream() {
        }

        @Override // java.io.ByteArrayOutputStream
        public void reset() {
            super.reset();
            Arrays.clear(this.buf);
        }

        void copy(byte[] bArr, int i) {
            System.arraycopy(this.buf, 0, bArr, i, size());
        }
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "NULL";
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return this.bOut.size();
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte b) {
        this.bOut.write(b);
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte[] bArr, int i, int i2) {
        this.bOut.write(bArr, i, i2);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        int size = this.bOut.size();
        this.bOut.copy(bArr, i);
        reset();
        return size;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this.bOut.reset();
    }
}