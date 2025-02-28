package org.bouncycastle.pqc.crypto.gmss;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.gmss.util.GMSSRandom;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/gmss/GMSSRootSig.class */
public class GMSSRootSig {
    private Digest messDigestOTS;
    private int mdsize;
    private int keysize;
    private byte[] privateKeyOTS;
    private byte[] hash;
    private byte[] sign;

    /* renamed from: w */
    private int f820w;
    private GMSSRandom gmssRandom;
    private int messagesize;

    /* renamed from: k */
    private int f821k;

    /* renamed from: r */
    private int f822r;
    private int test;
    private int counter;

    /* renamed from: ii */
    private int f823ii;
    private long test8;
    private long big8;
    private int steps;
    private int checksum;
    private int height;
    private byte[] seed;

    public GMSSRootSig(Digest digest, byte[][] bArr, int[] iArr) {
        this.messDigestOTS = digest;
        this.gmssRandom = new GMSSRandom(this.messDigestOTS);
        this.counter = iArr[0];
        this.test = iArr[1];
        this.f823ii = iArr[2];
        this.f822r = iArr[3];
        this.steps = iArr[4];
        this.keysize = iArr[5];
        this.height = iArr[6];
        this.f820w = iArr[7];
        this.checksum = iArr[8];
        this.mdsize = this.messDigestOTS.getDigestSize();
        this.f821k = (1 << this.f820w) - 1;
        this.messagesize = (int) Math.ceil((this.mdsize << 3) / this.f820w);
        this.privateKeyOTS = bArr[0];
        this.seed = bArr[1];
        this.hash = bArr[2];
        this.sign = bArr[3];
        this.test8 = (bArr[4][0] & 255) | ((bArr[4][1] & 255) << 8) | ((bArr[4][2] & 255) << 16) | ((bArr[4][3] & 255) << 24) | ((bArr[4][4] & 255) << 32) | ((bArr[4][5] & 255) << 40) | ((bArr[4][6] & 255) << 48) | ((bArr[4][7] & 255) << 56);
        this.big8 = (bArr[4][8] & 255) | ((bArr[4][9] & 255) << 8) | ((bArr[4][10] & 255) << 16) | ((bArr[4][11] & 255) << 24) | ((bArr[4][12] & 255) << 32) | ((bArr[4][13] & 255) << 40) | ((bArr[4][14] & 255) << 48) | ((bArr[4][15] & 255) << 56);
    }

    public GMSSRootSig(Digest digest, int i, int i2) {
        this.messDigestOTS = digest;
        this.gmssRandom = new GMSSRandom(this.messDigestOTS);
        this.mdsize = this.messDigestOTS.getDigestSize();
        this.f820w = i;
        this.height = i2;
        this.f821k = (1 << i) - 1;
        this.messagesize = (int) Math.ceil((this.mdsize << 3) / i);
    }

    public void initSign(byte[] bArr, byte[] bArr2) {
        this.hash = new byte[this.mdsize];
        this.messDigestOTS.update(bArr2, 0, bArr2.length);
        this.hash = new byte[this.messDigestOTS.getDigestSize()];
        this.messDigestOTS.doFinal(this.hash, 0);
        byte[] bArr3 = new byte[this.mdsize];
        System.arraycopy(this.hash, 0, bArr3, 0, this.mdsize);
        int i = 0;
        int log = getLog((this.messagesize << this.f820w) + 1);
        if (8 % this.f820w == 0) {
            int i2 = 8 / this.f820w;
            for (int i3 = 0; i3 < this.mdsize; i3++) {
                for (int i4 = 0; i4 < i2; i4++) {
                    i += bArr3[i3] & this.f821k;
                    bArr3[i3] = (byte) (bArr3[i3] >>> this.f820w);
                }
            }
            this.checksum = (this.messagesize << this.f820w) - i;
            int i5 = this.checksum;
            int i6 = 0;
            while (true) {
                int i7 = i6;
                if (i7 >= log) {
                    break;
                }
                i += i5 & this.f821k;
                i5 >>>= this.f820w;
                i6 = i7 + this.f820w;
            }
        } else if (this.f820w < 8) {
            int i8 = 0;
            int i9 = this.mdsize / this.f820w;
            for (int i10 = 0; i10 < i9; i10++) {
                long j = 0;
                for (int i11 = 0; i11 < this.f820w; i11++) {
                    j ^= (bArr3[i8] & 255) << (i11 << 3);
                    i8++;
                }
                for (int i12 = 0; i12 < 8; i12++) {
                    i += (int) (j & this.f821k);
                    j >>>= this.f820w;
                }
            }
            int i13 = this.mdsize % this.f820w;
            long j2 = 0;
            for (int i14 = 0; i14 < i13; i14++) {
                j2 ^= (bArr3[i8] & 255) << (i14 << 3);
                i8++;
            }
            int i15 = i13 << 3;
            int i16 = 0;
            while (true) {
                int i17 = i16;
                if (i17 >= i15) {
                    break;
                }
                i += (int) (j2 & this.f821k);
                j2 >>>= this.f820w;
                i16 = i17 + this.f820w;
            }
            this.checksum = (this.messagesize << this.f820w) - i;
            int i18 = this.checksum;
            int i19 = 0;
            while (true) {
                int i20 = i19;
                if (i20 >= log) {
                    break;
                }
                i += i18 & this.f821k;
                i18 >>>= this.f820w;
                i19 = i20 + this.f820w;
            }
        } else if (this.f820w < 57) {
            int i21 = 0;
            while (i21 <= (this.mdsize << 3) - this.f820w) {
                int i22 = i21 >>> 3;
                int i23 = i21 % 8;
                i21 += this.f820w;
                long j3 = 0;
                int i24 = 0;
                for (int i25 = i22; i25 < ((i21 + 7) >>> 3); i25++) {
                    j3 ^= (bArr3[i25] & 255) << (i24 << 3);
                    i24++;
                }
                i = (int) (i + ((j3 >>> i23) & this.f821k));
            }
            int i26 = i21 >>> 3;
            if (i26 < this.mdsize) {
                int i27 = i21 % 8;
                long j4 = 0;
                int i28 = 0;
                for (int i29 = i26; i29 < this.mdsize; i29++) {
                    j4 ^= (bArr3[i29] & 255) << (i28 << 3);
                    i28++;
                }
                i = (int) (i + ((j4 >>> i27) & this.f821k));
            }
            this.checksum = (this.messagesize << this.f820w) - i;
            int i30 = this.checksum;
            int i31 = 0;
            while (true) {
                int i32 = i31;
                if (i32 >= log) {
                    break;
                }
                i += i30 & this.f821k;
                i30 >>>= this.f820w;
                i31 = i32 + this.f820w;
            }
        }
        this.keysize = this.messagesize + ((int) Math.ceil(log / this.f820w));
        this.steps = (int) Math.ceil((this.keysize + i) / (1 << this.height));
        this.sign = new byte[this.keysize * this.mdsize];
        this.counter = 0;
        this.test = 0;
        this.f823ii = 0;
        this.test8 = 0L;
        this.f822r = 0;
        this.privateKeyOTS = new byte[this.mdsize];
        this.seed = new byte[this.mdsize];
        System.arraycopy(bArr, 0, this.seed, 0, this.mdsize);
    }

    public boolean updateSign() {
        for (int i = 0; i < this.steps; i++) {
            if (this.counter < this.keysize) {
                oneStep();
            }
            if (this.counter == this.keysize) {
                return true;
            }
        }
        return false;
    }

    public byte[] getSig() {
        return this.sign;
    }

    private void oneStep() {
        int i;
        if (8 % this.f820w == 0) {
            if (this.test == 0) {
                this.privateKeyOTS = this.gmssRandom.nextSeed(this.seed);
                if (this.f823ii < this.mdsize) {
                    this.test = this.hash[this.f823ii] & this.f821k;
                    this.hash[this.f823ii] = (byte) (this.hash[this.f823ii] >>> this.f820w);
                } else {
                    this.test = this.checksum & this.f821k;
                    this.checksum >>>= this.f820w;
                }
            } else if (this.test > 0) {
                this.messDigestOTS.update(this.privateKeyOTS, 0, this.privateKeyOTS.length);
                this.privateKeyOTS = new byte[this.messDigestOTS.getDigestSize()];
                this.messDigestOTS.doFinal(this.privateKeyOTS, 0);
                this.test--;
            }
            if (this.test == 0) {
                System.arraycopy(this.privateKeyOTS, 0, this.sign, this.counter * this.mdsize, this.mdsize);
                this.counter++;
                if (this.counter % (8 / this.f820w) == 0) {
                    this.f823ii++;
                }
            }
        } else if (this.f820w < 8) {
            if (this.test == 0) {
                if (this.counter % 8 == 0 && this.f823ii < this.mdsize) {
                    this.big8 = 0L;
                    if (this.counter < ((this.mdsize / this.f820w) << 3)) {
                        for (int i2 = 0; i2 < this.f820w; i2++) {
                            this.big8 ^= (this.hash[this.f823ii] & 255) << (i2 << 3);
                            this.f823ii++;
                        }
                    } else {
                        for (int i3 = 0; i3 < this.mdsize % this.f820w; i3++) {
                            this.big8 ^= (this.hash[this.f823ii] & 255) << (i3 << 3);
                            this.f823ii++;
                        }
                    }
                }
                if (this.counter == this.messagesize) {
                    this.big8 = this.checksum;
                }
                this.test = (int) (this.big8 & this.f821k);
                this.privateKeyOTS = this.gmssRandom.nextSeed(this.seed);
            } else if (this.test > 0) {
                this.messDigestOTS.update(this.privateKeyOTS, 0, this.privateKeyOTS.length);
                this.privateKeyOTS = new byte[this.messDigestOTS.getDigestSize()];
                this.messDigestOTS.doFinal(this.privateKeyOTS, 0);
                this.test--;
            }
            if (this.test == 0) {
                System.arraycopy(this.privateKeyOTS, 0, this.sign, this.counter * this.mdsize, this.mdsize);
                this.big8 >>>= this.f820w;
                this.counter++;
            }
        } else if (this.f820w < 57) {
            if (this.test8 == 0) {
                this.big8 = 0L;
                this.f823ii = 0;
                int i4 = this.f822r % 8;
                int i5 = this.f822r >>> 3;
                if (i5 < this.mdsize) {
                    if (this.f822r <= (this.mdsize << 3) - this.f820w) {
                        this.f822r += this.f820w;
                        i = (this.f822r + 7) >>> 3;
                    } else {
                        i = this.mdsize;
                        this.f822r += this.f820w;
                    }
                    for (int i6 = i5; i6 < i; i6++) {
                        this.big8 ^= (this.hash[i6] & 255) << (this.f823ii << 3);
                        this.f823ii++;
                    }
                    this.big8 >>>= i4;
                    this.test8 = this.big8 & this.f821k;
                } else {
                    this.test8 = this.checksum & this.f821k;
                    this.checksum >>>= this.f820w;
                }
                this.privateKeyOTS = this.gmssRandom.nextSeed(this.seed);
            } else if (this.test8 > 0) {
                this.messDigestOTS.update(this.privateKeyOTS, 0, this.privateKeyOTS.length);
                this.privateKeyOTS = new byte[this.messDigestOTS.getDigestSize()];
                this.messDigestOTS.doFinal(this.privateKeyOTS, 0);
                this.test8--;
            }
            if (this.test8 == 0) {
                System.arraycopy(this.privateKeyOTS, 0, this.sign, this.counter * this.mdsize, this.mdsize);
                this.counter++;
            }
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

    public byte[][] getStatByte() {
        return new byte[][]{this.privateKeyOTS, this.seed, this.hash, this.sign, getStatLong()};
    }

    public int[] getStatInt() {
        return new int[]{this.counter, this.test, this.f823ii, this.f822r, this.steps, this.keysize, this.height, this.f820w, this.checksum};
    }

    public byte[] getStatLong() {
        return new byte[]{(byte) (this.test8 & 255), (byte) ((this.test8 >> 8) & 255), (byte) ((this.test8 >> 16) & 255), (byte) ((this.test8 >> 24) & 255), (byte) ((this.test8 >> 32) & 255), (byte) ((this.test8 >> 40) & 255), (byte) ((this.test8 >> 48) & 255), (byte) ((this.test8 >> 56) & 255), (byte) (this.big8 & 255), (byte) ((this.big8 >> 8) & 255), (byte) ((this.big8 >> 16) & 255), (byte) ((this.big8 >> 24) & 255), (byte) ((this.big8 >> 32) & 255), (byte) ((this.big8 >> 40) & 255), (byte) ((this.big8 >> 48) & 255), (byte) ((this.big8 >> 56) & 255)};
    }

    public String toString() {
        String str = "" + this.big8 + "  ";
        int[] iArr = new int[9];
        int[] statInt = getStatInt();
        byte[][] bArr = new byte[5][this.mdsize];
        byte[][] statByte = getStatByte();
        for (int i = 0; i < 9; i++) {
            str = str + statInt[i] + " ";
        }
        for (int i2 = 0; i2 < 5; i2++) {
            str = str + new String(Hex.encode(statByte[i2])) + " ";
        }
        return str;
    }
}