package org.bouncycastle.pqc.crypto.frodo;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Pack;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public abstract class FrodoMatrixGenerator {

    /* renamed from: n */
    int f1258n;

    /* renamed from: q */
    int f1259q;

    /* loaded from: classes2.dex */
    static class Aes128MatrixGenerator extends FrodoMatrixGenerator {
        public Aes128MatrixGenerator(int i, int i2) {
            super(i, i2);
        }

        @Override // org.bouncycastle.pqc.crypto.frodo.FrodoMatrixGenerator
        short[] genMatrix(byte[] bArr) {
            short[] sArr = new short[this.f1258n * this.f1258n];
            byte[] bArr2 = new byte[16];
            byte[] bArr3 = new byte[16];
            AESEngine aESEngine = new AESEngine();
            aESEngine.init(true, new KeyParameter(bArr));
            for (int i = 0; i < this.f1258n; i++) {
                Pack.shortToLittleEndian((short) i, bArr2, 0);
                for (int i2 = 0; i2 < this.f1258n; i2 += 8) {
                    Pack.shortToLittleEndian((short) i2, bArr2, 2);
                    aESEngine.processBlock(bArr2, 0, bArr3, 0);
                    for (int i3 = 0; i3 < 8; i3++) {
                        sArr[(this.f1258n * i) + i2 + i3] = (short) (Pack.littleEndianToShort(bArr3, i3 * 2) & (this.f1259q - 1));
                    }
                }
            }
            return sArr;
        }
    }

    /* loaded from: classes2.dex */
    static class Shake128MatrixGenerator extends FrodoMatrixGenerator {
        public Shake128MatrixGenerator(int i, int i2) {
            super(i, i2);
        }

        @Override // org.bouncycastle.pqc.crypto.frodo.FrodoMatrixGenerator
        short[] genMatrix(byte[] bArr) {
            short[] sArr = new short[this.f1258n * this.f1258n];
            int i = (this.f1258n * 16) / 8;
            byte[] bArr2 = new byte[i];
            int length = bArr.length + 2;
            byte[] bArr3 = new byte[length];
            System.arraycopy(bArr, 0, bArr3, 2, bArr.length);
            SHAKEDigest sHAKEDigest = new SHAKEDigest(128);
            for (short s = 0; s < this.f1258n; s = (short) (s + 1)) {
                Pack.shortToLittleEndian(s, bArr3, 0);
                sHAKEDigest.update(bArr3, 0, length);
                sHAKEDigest.doFinal(bArr2, 0, i);
                for (short s2 = 0; s2 < this.f1258n; s2 = (short) (s2 + 1)) {
                    sArr[(this.f1258n * s) + s2] = (short) (Pack.littleEndianToShort(bArr2, s2 * 2) & (this.f1259q - 1));
                }
            }
            return sArr;
        }
    }

    public FrodoMatrixGenerator(int i, int i2) {
        this.f1258n = i;
        this.f1259q = i2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract short[] genMatrix(byte[] bArr);
}