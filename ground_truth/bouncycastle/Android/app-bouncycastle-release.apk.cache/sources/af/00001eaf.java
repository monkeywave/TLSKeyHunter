package org.bouncycastle.crypto.prng;

import org.bouncycastle.crypto.BlockCipher;

/* loaded from: classes2.dex */
public class X931RNG {
    private static final int BLOCK128_MAX_BITS_REQUEST = 262144;
    private static final long BLOCK128_RESEED_MAX = 8388608;
    private static final int BLOCK64_MAX_BITS_REQUEST = 4096;
    private static final long BLOCK64_RESEED_MAX = 32768;

    /* renamed from: DT */
    private final byte[] f887DT;

    /* renamed from: I */
    private final byte[] f888I;

    /* renamed from: R */
    private final byte[] f889R;

    /* renamed from: V */
    private byte[] f890V;
    private final BlockCipher engine;
    private final EntropySource entropySource;
    private long reseedCounter = 1;

    public X931RNG(BlockCipher blockCipher, byte[] bArr, EntropySource entropySource) {
        this.engine = blockCipher;
        this.entropySource = entropySource;
        byte[] bArr2 = new byte[blockCipher.getBlockSize()];
        this.f887DT = bArr2;
        System.arraycopy(bArr, 0, bArr2, 0, bArr2.length);
        this.f888I = new byte[blockCipher.getBlockSize()];
        this.f889R = new byte[blockCipher.getBlockSize()];
    }

    private void increment(byte[] bArr) {
        for (int length = bArr.length - 1; length >= 0; length--) {
            byte b = (byte) (bArr[length] + 1);
            bArr[length] = b;
            if (b != 0) {
                return;
            }
        }
    }

    private static boolean isTooLarge(byte[] bArr, int i) {
        return bArr != null && bArr.length > i;
    }

    private void process(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        for (int i = 0; i != bArr.length; i++) {
            bArr[i] = (byte) (bArr2[i] ^ bArr3[i]);
        }
        this.engine.processBlock(bArr, 0, bArr, 0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int generate(byte[] bArr, boolean z) {
        int length = this.f889R.length;
        long j = this.reseedCounter;
        if (length == 8) {
            if (j > BLOCK64_RESEED_MAX) {
                return -1;
            }
            if (isTooLarge(bArr, 512)) {
                throw new IllegalArgumentException("Number of bits per request limited to 4096");
            }
        } else if (j > BLOCK128_RESEED_MAX) {
            return -1;
        } else {
            if (isTooLarge(bArr, 32768)) {
                throw new IllegalArgumentException("Number of bits per request limited to 262144");
            }
        }
        if (z || this.f890V == null) {
            byte[] entropy = this.entropySource.getEntropy();
            this.f890V = entropy;
            if (entropy.length != this.engine.getBlockSize()) {
                throw new IllegalStateException("Insufficient entropy returned");
            }
        }
        int length2 = bArr.length / this.f889R.length;
        for (int i = 0; i < length2; i++) {
            this.engine.processBlock(this.f887DT, 0, this.f888I, 0);
            process(this.f889R, this.f888I, this.f890V);
            process(this.f890V, this.f889R, this.f888I);
            byte[] bArr2 = this.f889R;
            System.arraycopy(bArr2, 0, bArr, bArr2.length * i, bArr2.length);
            increment(this.f887DT);
        }
        int length3 = bArr.length - (this.f889R.length * length2);
        if (length3 > 0) {
            this.engine.processBlock(this.f887DT, 0, this.f888I, 0);
            process(this.f889R, this.f888I, this.f890V);
            process(this.f890V, this.f889R, this.f888I);
            byte[] bArr3 = this.f889R;
            System.arraycopy(bArr3, 0, bArr, length2 * bArr3.length, length3);
            increment(this.f887DT);
        }
        this.reseedCounter++;
        return bArr.length * 8;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public EntropySource getEntropySource() {
        return this.entropySource;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void reseed() {
        byte[] entropy = this.entropySource.getEntropy();
        this.f890V = entropy;
        if (entropy.length != this.engine.getBlockSize()) {
            throw new IllegalStateException("Insufficient entropy returned");
        }
        this.reseedCounter = 1L;
    }
}