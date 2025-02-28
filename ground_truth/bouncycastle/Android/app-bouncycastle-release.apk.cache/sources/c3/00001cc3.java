package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.p019io.LimitedBuffer;

/* loaded from: classes2.dex */
public class Prehash implements Digest {
    private final String algorithmName;
    private final LimitedBuffer buf;

    private Prehash(Digest digest) {
        this.algorithmName = digest.getAlgorithmName();
        this.buf = new LimitedBuffer(digest.getDigestSize());
    }

    public static Prehash forDigest(Digest digest) {
        return new Prehash(digest);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        try {
            if (getDigestSize() == this.buf.size()) {
                return this.buf.copyTo(bArr, i);
            }
            throw new IllegalStateException("Incorrect prehash size");
        } finally {
            reset();
        }
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return this.algorithmName;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return this.buf.limit();
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this.buf.reset();
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte b) {
        this.buf.write(b);
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte[] bArr, int i, int i2) {
        this.buf.write(bArr, i, i2);
    }
}