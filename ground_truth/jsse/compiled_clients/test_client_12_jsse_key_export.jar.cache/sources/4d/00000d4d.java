package org.bouncycastle.pqc.crypto.gmss.util;

import org.bouncycastle.crypto.Digest;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/gmss/util/WinternitzOTSignature.class */
public class WinternitzOTSignature {
    private Digest messDigestOTS;
    private int mdsize;
    private int keysize;
    private byte[][] privateKeyOTS;

    /* renamed from: w */
    private int f825w;
    private GMSSRandom gmssRandom;
    private int messagesize;
    private int checksumsize;

    /* JADX WARN: Type inference failed for: r1v19, types: [byte[], byte[][]] */
    public WinternitzOTSignature(byte[] bArr, Digest digest, int i) {
        this.f825w = i;
        this.messDigestOTS = digest;
        this.gmssRandom = new GMSSRandom(this.messDigestOTS);
        this.mdsize = this.messDigestOTS.getDigestSize();
        this.messagesize = (((this.mdsize << 3) + i) - 1) / i;
        this.checksumsize = getLog((this.messagesize << i) + 1);
        this.keysize = this.messagesize + (((this.checksumsize + i) - 1) / i);
        this.privateKeyOTS = new byte[this.keysize];
        byte[] bArr2 = new byte[this.mdsize];
        System.arraycopy(bArr, 0, bArr2, 0, bArr2.length);
        for (int i2 = 0; i2 < this.keysize; i2++) {
            this.privateKeyOTS[i2] = this.gmssRandom.nextSeed(bArr2);
        }
    }

    public byte[][] getPrivateKey() {
        return this.privateKeyOTS;
    }

    public byte[] getPublicKey() {
        byte[] bArr = new byte[this.keysize * this.mdsize];
        int i = 0;
        int i2 = (1 << this.f825w) - 1;
        for (int i3 = 0; i3 < this.keysize; i3++) {
            hashPrivateKeyBlock(i3, i2, bArr, i);
            i += this.mdsize;
        }
        this.messDigestOTS.update(bArr, 0, bArr.length);
        byte[] bArr2 = new byte[this.mdsize];
        this.messDigestOTS.doFinal(bArr2, 0);
        return bArr2;
    }

    public byte[] getSignature(byte[] bArr) {
        byte[] bArr2 = new byte[this.keysize * this.mdsize];
        byte[] bArr3 = new byte[this.mdsize];
        int i = 0;
        int i2 = 0;
        this.messDigestOTS.update(bArr, 0, bArr.length);
        this.messDigestOTS.doFinal(bArr3, 0);
        if (8 % this.f825w == 0) {
            int i3 = 8 / this.f825w;
            int i4 = (1 << this.f825w) - 1;
            for (int i5 = 0; i5 < bArr3.length; i5++) {
                for (int i6 = 0; i6 < i3; i6++) {
                    int i7 = bArr3[i5] & i4;
                    i2 += i7;
                    hashPrivateKeyBlock(i, i7, bArr2, i * this.mdsize);
                    bArr3[i5] = (byte) (bArr3[i5] >>> this.f825w);
                    i++;
                }
            }
            int i8 = (this.messagesize << this.f825w) - i2;
            int i9 = 0;
            while (true) {
                int i10 = i9;
                if (i10 >= this.checksumsize) {
                    break;
                }
                hashPrivateKeyBlock(i, i8 & i4, bArr2, i * this.mdsize);
                i8 >>>= this.f825w;
                i++;
                i9 = i10 + this.f825w;
            }
        } else if (this.f825w < 8) {
            int i11 = this.mdsize / this.f825w;
            int i12 = (1 << this.f825w) - 1;
            int i13 = 0;
            for (int i14 = 0; i14 < i11; i14++) {
                long j = 0;
                for (int i15 = 0; i15 < this.f825w; i15++) {
                    j ^= (bArr3[i13] & 255) << (i15 << 3);
                    i13++;
                }
                for (int i16 = 0; i16 < 8; i16++) {
                    int i17 = ((int) j) & i12;
                    i2 += i17;
                    hashPrivateKeyBlock(i, i17, bArr2, i * this.mdsize);
                    j >>>= this.f825w;
                    i++;
                }
            }
            int i18 = this.mdsize % this.f825w;
            long j2 = 0;
            for (int i19 = 0; i19 < i18; i19++) {
                j2 ^= (bArr3[i13] & 255) << (i19 << 3);
                i13++;
            }
            int i20 = i18 << 3;
            int i21 = 0;
            while (true) {
                int i22 = i21;
                if (i22 >= i20) {
                    break;
                }
                int i23 = ((int) j2) & i12;
                i2 += i23;
                hashPrivateKeyBlock(i, i23, bArr2, i * this.mdsize);
                j2 >>>= this.f825w;
                i++;
                i21 = i22 + this.f825w;
            }
            int i24 = (this.messagesize << this.f825w) - i2;
            int i25 = 0;
            while (true) {
                int i26 = i25;
                if (i26 >= this.checksumsize) {
                    break;
                }
                hashPrivateKeyBlock(i, i24 & i12, bArr2, i * this.mdsize);
                i24 >>>= this.f825w;
                i++;
                i25 = i26 + this.f825w;
            }
        } else if (this.f825w < 57) {
            int i27 = (this.mdsize << 3) - this.f825w;
            int i28 = (1 << this.f825w) - 1;
            byte[] bArr4 = new byte[this.mdsize];
            int i29 = 0;
            while (i29 <= i27) {
                int i30 = i29 >>> 3;
                int i31 = i29 % 8;
                i29 += this.f825w;
                long j3 = 0;
                int i32 = 0;
                for (int i33 = i30; i33 < ((i29 + 7) >>> 3); i33++) {
                    j3 ^= (bArr3[i33] & 255) << (i32 << 3);
                    i32++;
                }
                long j4 = (j3 >>> i31) & i28;
                i2 = (int) (i2 + j4);
                System.arraycopy(this.privateKeyOTS[i], 0, bArr4, 0, this.mdsize);
                while (j4 > 0) {
                    this.messDigestOTS.update(bArr4, 0, bArr4.length);
                    this.messDigestOTS.doFinal(bArr4, 0);
                    j4--;
                }
                System.arraycopy(bArr4, 0, bArr2, i * this.mdsize, this.mdsize);
                i++;
            }
            int i34 = i29 >>> 3;
            if (i34 < this.mdsize) {
                int i35 = i29 % 8;
                long j5 = 0;
                int i36 = 0;
                for (int i37 = i34; i37 < this.mdsize; i37++) {
                    j5 ^= (bArr3[i37] & 255) << (i36 << 3);
                    i36++;
                }
                long j6 = (j5 >>> i35) & i28;
                i2 = (int) (i2 + j6);
                System.arraycopy(this.privateKeyOTS[i], 0, bArr4, 0, this.mdsize);
                while (j6 > 0) {
                    this.messDigestOTS.update(bArr4, 0, bArr4.length);
                    this.messDigestOTS.doFinal(bArr4, 0);
                    j6--;
                }
                System.arraycopy(bArr4, 0, bArr2, i * this.mdsize, this.mdsize);
                i++;
            }
            int i38 = (this.messagesize << this.f825w) - i2;
            int i39 = 0;
            while (true) {
                int i40 = i39;
                if (i40 >= this.checksumsize) {
                    break;
                }
                System.arraycopy(this.privateKeyOTS[i], 0, bArr4, 0, this.mdsize);
                for (long j7 = i38 & i28; j7 > 0; j7--) {
                    this.messDigestOTS.update(bArr4, 0, bArr4.length);
                    this.messDigestOTS.doFinal(bArr4, 0);
                }
                System.arraycopy(bArr4, 0, bArr2, i * this.mdsize, this.mdsize);
                i38 >>>= this.f825w;
                i++;
                i39 = i40 + this.f825w;
            }
        }
        return bArr2;
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

    private void hashPrivateKeyBlock(int i, int i2, byte[] bArr, int i3) {
        if (i2 < 1) {
            System.arraycopy(this.privateKeyOTS[i], 0, bArr, i3, this.mdsize);
            return;
        }
        this.messDigestOTS.update(this.privateKeyOTS[i], 0, this.mdsize);
        this.messDigestOTS.doFinal(bArr, i3);
        while (true) {
            i2--;
            if (i2 <= 0) {
                return;
            }
            this.messDigestOTS.update(bArr, i3, this.mdsize);
            this.messDigestOTS.doFinal(bArr, i3);
        }
    }
}