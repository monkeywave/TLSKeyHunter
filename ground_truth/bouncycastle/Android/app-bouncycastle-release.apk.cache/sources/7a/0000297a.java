package org.bouncycastle.pqc.crypto.crystals.dilithium;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.tls.CipherSuite;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public abstract class Symmetric {
    final int stream128BlockBytes;
    final int stream256BlockBytes;

    /* JADX INFO: Access modifiers changed from: package-private */
    @Deprecated
    /* loaded from: classes2.dex */
    public static class AesSymmetric extends Symmetric {
        private final StreamCipher cipher;

        /* JADX INFO: Access modifiers changed from: package-private */
        public AesSymmetric() {
            super(64, 64);
            this.cipher = SICBlockCipher.newInstance(AESEngine.newInstance());
        }

        private void aes128(byte[] bArr, int i, int i2) {
            this.cipher.processBytes(new byte[i2], 0, i2, bArr, i);
        }

        private void streamInit(byte[] bArr, short s) {
            byte[] bArr2 = new byte[12];
            bArr2[0] = (byte) s;
            bArr2[1] = (byte) (s >> 8);
            this.cipher.init(true, new ParametersWithIV(new KeyParameter(bArr, 0, 32), bArr2));
        }

        @Override // org.bouncycastle.pqc.crypto.crystals.dilithium.Symmetric
        void stream128init(byte[] bArr, short s) {
            streamInit(bArr, s);
        }

        @Override // org.bouncycastle.pqc.crypto.crystals.dilithium.Symmetric
        void stream128squeezeBlocks(byte[] bArr, int i, int i2) {
            aes128(bArr, i, i2);
        }

        @Override // org.bouncycastle.pqc.crypto.crystals.dilithium.Symmetric
        void stream256init(byte[] bArr, short s) {
            streamInit(bArr, s);
        }

        @Override // org.bouncycastle.pqc.crypto.crystals.dilithium.Symmetric
        void stream256squeezeBlocks(byte[] bArr, int i, int i2) {
            aes128(bArr, i, i2);
        }
    }

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

        @Override // org.bouncycastle.pqc.crypto.crystals.dilithium.Symmetric
        void stream128init(byte[] bArr, short s) {
            streamInit(this.digest128, bArr, s);
        }

        @Override // org.bouncycastle.pqc.crypto.crystals.dilithium.Symmetric
        void stream128squeezeBlocks(byte[] bArr, int i, int i2) {
            this.digest128.doOutput(bArr, i, i2);
        }

        @Override // org.bouncycastle.pqc.crypto.crystals.dilithium.Symmetric
        void stream256init(byte[] bArr, short s) {
            streamInit(this.digest256, bArr, s);
        }

        @Override // org.bouncycastle.pqc.crypto.crystals.dilithium.Symmetric
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