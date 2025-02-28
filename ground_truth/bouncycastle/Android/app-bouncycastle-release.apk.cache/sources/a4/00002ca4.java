package org.bouncycastle.pqc.legacy.crypto.gmss.util;

import kotlin.UByte;
import org.bouncycastle.crypto.Digest;

/* loaded from: classes2.dex */
public class WinternitzOTSignature {
    private int checksumsize;
    private GMSSRandom gmssRandom;
    private int keysize;
    private int mdsize;
    private Digest messDigestOTS;
    private int messagesize;
    private byte[][] privateKeyOTS;

    /* renamed from: w */
    private int f1476w;

    public WinternitzOTSignature(byte[] bArr, Digest digest, int i) {
        this.f1476w = i;
        this.messDigestOTS = digest;
        this.gmssRandom = new GMSSRandom(this.messDigestOTS);
        int digestSize = this.messDigestOTS.getDigestSize();
        this.mdsize = digestSize;
        int i2 = (((digestSize << 3) + i) - 1) / i;
        this.messagesize = i2;
        int log = getLog((i2 << i) + 1);
        this.checksumsize = log;
        int i3 = this.messagesize + (((log + i) - 1) / i);
        this.keysize = i3;
        this.privateKeyOTS = new byte[i3];
        int i4 = this.mdsize;
        byte[] bArr2 = new byte[i4];
        System.arraycopy(bArr, 0, bArr2, 0, i4);
        for (int i5 = 0; i5 < this.keysize; i5++) {
            this.privateKeyOTS[i5] = this.gmssRandom.nextSeed(bArr2);
        }
    }

    private void hashPrivateKeyBlock(int i, int i2, byte[] bArr, int i3) {
        if (i2 < 1) {
            System.arraycopy(this.privateKeyOTS[i], 0, bArr, i3, this.mdsize);
            return;
        }
        this.messDigestOTS.update(this.privateKeyOTS[i], 0, this.mdsize);
        while (true) {
            this.messDigestOTS.doFinal(bArr, i3);
            i2--;
            if (i2 <= 0) {
                return;
            }
            this.messDigestOTS.update(bArr, i3, this.mdsize);
        }
    }

    public int getLog(int i) {
        int i2 = 1;
        int i3 = 2;
        while (i3 < i) {
            i3 <<= 1;
            i2++;
        }
        return i2;
    }

    public byte[][] getPrivateKey() {
        return this.privateKeyOTS;
    }

    public byte[] getPublicKey() {
        int i = this.keysize * this.mdsize;
        byte[] bArr = new byte[i];
        int i2 = (1 << this.f1476w) - 1;
        int i3 = 0;
        for (int i4 = 0; i4 < this.keysize; i4++) {
            hashPrivateKeyBlock(i4, i2, bArr, i3);
            i3 += this.mdsize;
        }
        this.messDigestOTS.update(bArr, 0, i);
        byte[] bArr2 = new byte[this.mdsize];
        this.messDigestOTS.doFinal(bArr2, 0);
        return bArr2;
    }

    public byte[] getSignature(byte[] bArr) {
        int i;
        int i2 = this.keysize;
        int i3 = this.mdsize;
        byte[] bArr2 = new byte[i2 * i3];
        byte[] bArr3 = new byte[i3];
        int i4 = 0;
        this.messDigestOTS.update(bArr, 0, bArr.length);
        this.messDigestOTS.doFinal(bArr3, 0);
        int i5 = this.f1476w;
        int i6 = 8;
        if (8 % i5 == 0) {
            int i7 = 8 / i5;
            int i8 = (1 << i5) - 1;
            int i9 = 0;
            int i10 = 0;
            for (int i11 = 0; i11 < i3; i11++) {
                for (int i12 = 0; i12 < i7; i12++) {
                    int i13 = bArr3[i11] & i8;
                    i9 += i13;
                    hashPrivateKeyBlock(i10, i13, bArr2, this.mdsize * i10);
                    bArr3[i11] = (byte) (bArr3[i11] >>> this.f1476w);
                    i10++;
                }
            }
            int i14 = (this.messagesize << this.f1476w) - i9;
            while (i4 < this.checksumsize) {
                hashPrivateKeyBlock(i10, i14 & i8, bArr2, this.mdsize * i10);
                int i15 = this.f1476w;
                i14 >>>= i15;
                i10++;
                i4 += i15;
            }
        } else if (i5 < 8) {
            int i16 = this.mdsize / i5;
            int i17 = (1 << i5) - 1;
            int i18 = 0;
            int i19 = 0;
            int i20 = 0;
            int i21 = 0;
            while (i18 < i16) {
                long j = 0;
                for (int i22 = 0; i22 < this.f1476w; i22++) {
                    j ^= (bArr3[i19] & UByte.MAX_VALUE) << (i22 << 3);
                    i19++;
                }
                int i23 = 0;
                long j2 = j;
                while (i23 < i6) {
                    int i24 = ((int) j2) & i17;
                    i21 += i24;
                    hashPrivateKeyBlock(i20, i24, bArr2, this.mdsize * i20);
                    j2 >>>= this.f1476w;
                    i20++;
                    i23++;
                    i6 = 8;
                }
                i18++;
                i6 = 8;
            }
            int i25 = this.mdsize % this.f1476w;
            long j3 = 0;
            for (int i26 = 0; i26 < i25; i26++) {
                j3 ^= (bArr3[i19] & UByte.MAX_VALUE) << (i26 << 3);
                i19++;
            }
            int i27 = i25 << 3;
            int i28 = 0;
            while (i28 < i27) {
                int i29 = ((int) j3) & i17;
                i21 += i29;
                hashPrivateKeyBlock(i20, i29, bArr2, this.mdsize * i20);
                int i30 = this.f1476w;
                j3 >>>= i30;
                i20++;
                i28 += i30;
            }
            int i31 = (this.messagesize << this.f1476w) - i21;
            while (i4 < this.checksumsize) {
                hashPrivateKeyBlock(i20, i31 & i17, bArr2, this.mdsize * i20);
                int i32 = this.f1476w;
                i31 >>>= i32;
                i20++;
                i4 += i32;
            }
        } else if (i5 < 57) {
            int i33 = this.mdsize;
            int i34 = (i33 << 3) - i5;
            int i35 = (1 << i5) - 1;
            byte[] bArr4 = new byte[i33];
            int i36 = 0;
            int i37 = 0;
            int i38 = 0;
            while (i36 <= i34) {
                int i39 = i36 >>> 3;
                int i40 = i36 % 8;
                i36 += this.f1476w;
                int i41 = i4;
                long j4 = 0;
                while (i39 < ((i36 + 7) >>> 3)) {
                    j4 ^= (bArr3[i39] & UByte.MAX_VALUE) << (i41 << 3);
                    i41++;
                    i39++;
                    bArr3 = bArr3;
                    i34 = i34;
                }
                byte[] bArr5 = bArr3;
                int i42 = i34;
                long j5 = (j4 >>> i40) & i35;
                i38 = (int) (i38 + j5);
                System.arraycopy(this.privateKeyOTS[i37], 0, bArr4, 0, this.mdsize);
                while (j5 > 0) {
                    this.messDigestOTS.update(bArr4, 0, i33);
                    this.messDigestOTS.doFinal(bArr4, 0);
                    j5--;
                }
                int i43 = this.mdsize;
                System.arraycopy(bArr4, 0, bArr2, i37 * i43, i43);
                i37++;
                bArr3 = bArr5;
                i34 = i42;
                i4 = 0;
            }
            byte[] bArr6 = bArr3;
            int i44 = i36 >>> 3;
            if (i44 < this.mdsize) {
                int i45 = i36 % 8;
                int i46 = 0;
                long j6 = 0;
                while (true) {
                    i = this.mdsize;
                    if (i44 >= i) {
                        break;
                    }
                    j6 ^= (bArr6[i44] & UByte.MAX_VALUE) << (i46 << 3);
                    i46++;
                    i44++;
                }
                long j7 = (j6 >>> i45) & i35;
                i38 = (int) (i38 + j7);
                System.arraycopy(this.privateKeyOTS[i37], 0, bArr4, 0, i);
                while (j7 > 0) {
                    this.messDigestOTS.update(bArr4, 0, i33);
                    this.messDigestOTS.doFinal(bArr4, 0);
                    j7--;
                }
                int i47 = this.mdsize;
                System.arraycopy(bArr4, 0, bArr2, i37 * i47, i47);
                i37++;
            }
            int i48 = (this.messagesize << this.f1476w) - i38;
            int i49 = 0;
            while (i49 < this.checksumsize) {
                System.arraycopy(this.privateKeyOTS[i37], 0, bArr4, 0, this.mdsize);
                for (long j8 = i48 & i35; j8 > 0; j8--) {
                    this.messDigestOTS.update(bArr4, 0, i33);
                    this.messDigestOTS.doFinal(bArr4, 0);
                }
                int i50 = this.mdsize;
                System.arraycopy(bArr4, 0, bArr2, i37 * i50, i50);
                int i51 = this.f1476w;
                i48 >>>= i51;
                i37++;
                i49 += i51;
            }
        }
        return bArr2;
    }
}