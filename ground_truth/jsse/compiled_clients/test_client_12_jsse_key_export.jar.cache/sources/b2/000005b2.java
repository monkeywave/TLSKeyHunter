package org.bouncycastle.crypto.prng;

import org.bouncycastle.crypto.BlockCipher;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/prng/X931RNG.class */
public class X931RNG {
    private static final long BLOCK64_RESEED_MAX = 32768;
    private static final long BLOCK128_RESEED_MAX = 8388608;
    private static final int BLOCK64_MAX_BITS_REQUEST = 4096;
    private static final int BLOCK128_MAX_BITS_REQUEST = 262144;
    private final BlockCipher engine;
    private final EntropySource entropySource;

    /* renamed from: DT */
    private final byte[] f569DT;

    /* renamed from: I */
    private final byte[] f570I;

    /* renamed from: R */
    private final byte[] f571R;

    /* renamed from: V */
    private byte[] f572V;
    private long reseedCounter = 1;

    public X931RNG(BlockCipher blockCipher, byte[] bArr, EntropySource entropySource) {
        this.engine = blockCipher;
        this.entropySource = entropySource;
        this.f569DT = new byte[blockCipher.getBlockSize()];
        System.arraycopy(bArr, 0, this.f569DT, 0, this.f569DT.length);
        this.f570I = new byte[blockCipher.getBlockSize()];
        this.f571R = new byte[blockCipher.getBlockSize()];
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int generate(byte[] bArr, boolean z) {
        if (this.f571R.length == 8) {
            if (this.reseedCounter > BLOCK64_RESEED_MAX) {
                return -1;
            }
            if (isTooLarge(bArr, 512)) {
                throw new IllegalArgumentException("Number of bits per request limited to 4096");
            }
        } else if (this.reseedCounter > BLOCK128_RESEED_MAX) {
            return -1;
        } else {
            if (isTooLarge(bArr, 32768)) {
                throw new IllegalArgumentException("Number of bits per request limited to 262144");
            }
        }
        if (z || this.f572V == null) {
            this.f572V = this.entropySource.getEntropy();
            if (this.f572V.length != this.engine.getBlockSize()) {
                throw new IllegalStateException("Insufficient entropy returned");
            }
        }
        int length = bArr.length / this.f571R.length;
        for (int i = 0; i < length; i++) {
            this.engine.processBlock(this.f569DT, 0, this.f570I, 0);
            process(this.f571R, this.f570I, this.f572V);
            process(this.f572V, this.f571R, this.f570I);
            System.arraycopy(this.f571R, 0, bArr, i * this.f571R.length, this.f571R.length);
            increment(this.f569DT);
        }
        int length2 = bArr.length - (length * this.f571R.length);
        if (length2 > 0) {
            this.engine.processBlock(this.f569DT, 0, this.f570I, 0);
            process(this.f571R, this.f570I, this.f572V);
            process(this.f572V, this.f571R, this.f570I);
            System.arraycopy(this.f571R, 0, bArr, length * this.f571R.length, length2);
            increment(this.f569DT);
        }
        this.reseedCounter++;
        return bArr.length;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void reseed() {
        this.f572V = this.entropySource.getEntropy();
        if (this.f572V.length != this.engine.getBlockSize()) {
            throw new IllegalStateException("Insufficient entropy returned");
        }
        this.reseedCounter = 1L;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public EntropySource getEntropySource() {
        return this.entropySource;
    }

    private void process(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        for (int i = 0; i != bArr.length; i++) {
            bArr[i] = (byte) (bArr2[i] ^ bArr3[i]);
        }
        this.engine.processBlock(bArr, 0, bArr, 0);
    }

    private void increment(byte[] bArr) {
        for (int length = bArr.length - 1; length >= 0; length--) {
            int i = length;
            byte b = (byte) (bArr[i] + 1);
            bArr[i] = b;
            if (b != 0) {
                return;
            }
        }
    }

    private static boolean isTooLarge(byte[] bArr, int i) {
        return bArr != null && bArr.length > i;
    }
}