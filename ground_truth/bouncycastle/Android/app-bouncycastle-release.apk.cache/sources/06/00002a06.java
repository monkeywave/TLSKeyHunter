package org.bouncycastle.pqc.crypto.mldsa;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.tls.CipherSuite;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public abstract class Symmetric {
    final int stream128BlockBytes;
    final int stream256BlockBytes;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes2.dex */
    public static class ShakeSymmetric extends Symmetric {
        private final SHAKEDigest digest128;
        private final SHAKEDigest digest256;

        /* JADX INFO: Access modifiers changed from: package-private */
        public ShakeSymmetric() {
            super(CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA);
            this.digest128 = new SHAKEDigest(128);
            this.digest256 = new SHAKEDigest(256);
        }

        private void streamInit(SHAKEDigest sHAKEDigest, byte[] bArr, short s) {
            sHAKEDigest.reset();
            sHAKEDigest.update(bArr, 0, bArr.length);
            sHAKEDigest.update(new byte[]{(byte) s, (byte) (s >> 8)}, 0, 2);
        }

        @Override // org.bouncycastle.pqc.crypto.mldsa.Symmetric
        void stream128init(byte[] bArr, short s) {
            streamInit(this.digest128, bArr, s);
        }

        @Override // org.bouncycastle.pqc.crypto.mldsa.Symmetric
        void stream128squeezeBlocks(byte[] bArr, int i, int i2) {
            this.digest128.doOutput(bArr, i, i2);
        }

        @Override // org.bouncycastle.pqc.crypto.mldsa.Symmetric
        void stream256init(byte[] bArr, short s) {
            streamInit(this.digest256, bArr, s);
        }

        @Override // org.bouncycastle.pqc.crypto.mldsa.Symmetric
        void stream256squeezeBlocks(byte[] bArr, int i, int i2) {
            this.digest256.doOutput(bArr, i, i2);
        }
    }

    Symmetric(int i, int i2) {
        this.stream128BlockBytes = i;
        this.stream256BlockBytes = i2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void stream128init(byte[] bArr, short s);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void stream128squeezeBlocks(byte[] bArr, int i, int i2);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void stream256init(byte[] bArr, short s);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void stream256squeezeBlocks(byte[] bArr, int i, int i2);
}