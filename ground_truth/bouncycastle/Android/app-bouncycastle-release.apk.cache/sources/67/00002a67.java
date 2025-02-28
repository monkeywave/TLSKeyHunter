package org.bouncycastle.pqc.crypto.rainbow;

import java.security.SecureRandom;
import kotlin.UByte;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
class RainbowDRBG extends SecureRandom {
    private Digest hashAlgo;
    private byte[] key;
    private byte[] seed;

    /* renamed from: v */
    private byte[] f1370v;

    public RainbowDRBG(byte[] bArr, Digest digest) {
        this.seed = bArr;
        this.hashAlgo = digest;
        init(256);
    }

    private void AES256_CTR_DRBG_Update(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        byte[] bArr4 = new byte[48];
        for (int i = 0; i < 3; i++) {
            int i2 = 15;
            while (true) {
                if (i2 >= 0) {
                    byte b = bArr3[i2];
                    if ((b & UByte.MAX_VALUE) != 255) {
                        bArr3[i2] = (byte) (b + 1);
                        break;
                    } else {
                        bArr3[i2] = 0;
                        i2--;
                    }
                }
            }
            AES256_ECB(bArr2, bArr3, bArr4, i * 16);
        }
        if (bArr != null) {
            for (int i3 = 0; i3 < 48; i3++) {
                bArr4[i3] = (byte) (bArr4[i3] ^ bArr[i3]);
            }
        }
        System.arraycopy(bArr4, 0, bArr2, 0, bArr2.length);
        System.arraycopy(bArr4, 32, bArr3, 0, bArr3.length);
    }

    private void AES256_ECB(byte[] bArr, byte[] bArr2, byte[] bArr3, int i) {
        try {
            AESEngine aESEngine = new AESEngine();
            aESEngine.init(true, new KeyParameter(bArr));
            for (int i2 = 0; i2 != bArr2.length; i2 += 16) {
                aESEngine.processBlock(bArr2, i2, bArr3, i + i2);
            }
        } catch (Throwable th) {
            throw new IllegalStateException("drbg failure: " + th.getMessage(), th);
        }
    }

    private void init(int i) {
        byte[] bArr = this.seed;
        if (bArr.length >= 48) {
            randombytes_init(bArr, i);
            return;
        }
        randombytes_init(Arrays.concatenate(this.seed, RainbowUtil.hash(this.hashAlgo, bArr, 48 - bArr.length)), i);
    }

    private void randombytes_init(byte[] bArr, int i) {
        byte[] bArr2 = new byte[48];
        System.arraycopy(bArr, 0, bArr2, 0, 48);
        byte[] bArr3 = new byte[32];
        this.key = bArr3;
        byte[] bArr4 = new byte[16];
        this.f1370v = bArr4;
        AES256_CTR_DRBG_Update(bArr2, bArr3, bArr4);
    }

    @Override // java.security.SecureRandom, java.util.Random
    public void nextBytes(byte[] bArr) {
        byte[] bArr2 = new byte[16];
        int length = bArr.length;
        int i = 0;
        while (length > 0) {
            int i2 = 15;
            while (true) {
                if (i2 < 0) {
                    break;
                }
                byte[] bArr3 = this.f1370v;
                byte b = bArr3[i2];
                if ((b & UByte.MAX_VALUE) != 255) {
                    bArr3[i2] = (byte) (b + 1);
                    break;
                } else {
                    bArr3[i2] = 0;
                    i2--;
                }
            }
            AES256_ECB(this.key, this.f1370v, bArr2, 0);
            if (length > 15) {
                System.arraycopy(bArr2, 0, bArr, i, 16);
                i += 16;
                length -= 16;
            } else {
                System.arraycopy(bArr2, 0, bArr, i, length);
                length = 0;
            }
        }
        AES256_CTR_DRBG_Update(null, this.key, this.f1370v);
    }
}