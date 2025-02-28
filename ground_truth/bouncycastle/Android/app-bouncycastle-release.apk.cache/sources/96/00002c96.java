package org.bouncycastle.pqc.legacy.crypto.gmss;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.legacy.crypto.gmss.util.GMSSRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: classes2.dex */
public class GMSSLeaf {
    private byte[] concHashs;
    private GMSSRandom gmssRandom;

    /* renamed from: i */
    private int f1465i;

    /* renamed from: j */
    private int f1466j;
    private int keysize;
    private byte[] leaf;
    private int mdsize;
    private Digest messDigestOTS;
    byte[] privateKeyOTS;
    private byte[] seed;
    private int steps;
    private int two_power_w;

    /* renamed from: w */
    private int f1467w;

    /* JADX INFO: Access modifiers changed from: package-private */
    public GMSSLeaf(Digest digest, int i, int i2) {
        int digestSize;
        int ceil;
        int ceil2;
        int i3;
        this.f1467w = i;
        this.messDigestOTS = digest;
        this.gmssRandom = new GMSSRandom(this.messDigestOTS);
        this.mdsize = this.messDigestOTS.getDigestSize();
        double d = i;
        this.keysize = ((int) Math.ceil((digestSize << 3) / d)) + ((int) Math.ceil(getLog((ceil << i) + 1) / d));
        this.two_power_w = 1 << i;
        this.steps = (int) Math.ceil(((((i3 - 1) * ceil2) + 1) + ceil2) / i2);
        int i4 = this.mdsize;
        this.seed = new byte[i4];
        this.leaf = new byte[i4];
        this.privateKeyOTS = new byte[i4];
        this.concHashs = new byte[i4 * this.keysize];
    }

    public GMSSLeaf(Digest digest, int i, int i2, byte[] bArr) {
        int digestSize;
        int ceil;
        int ceil2;
        int i3;
        this.f1467w = i;
        this.messDigestOTS = digest;
        this.gmssRandom = new GMSSRandom(this.messDigestOTS);
        this.mdsize = this.messDigestOTS.getDigestSize();
        double d = i;
        this.keysize = ((int) Math.ceil((digestSize << 3) / d)) + ((int) Math.ceil(getLog((ceil << i) + 1) / d));
        this.two_power_w = 1 << i;
        this.steps = (int) Math.ceil(((((i3 - 1) * ceil2) + 1) + ceil2) / i2);
        int i4 = this.mdsize;
        this.seed = new byte[i4];
        this.leaf = new byte[i4];
        this.privateKeyOTS = new byte[i4];
        this.concHashs = new byte[i4 * this.keysize];
        initLeafCalc(bArr);
    }

    public GMSSLeaf(Digest digest, byte[][] bArr, int[] iArr) {
        this.f1465i = iArr[0];
        this.f1466j = iArr[1];
        this.steps = iArr[2];
        this.f1467w = iArr[3];
        this.messDigestOTS = digest;
        this.gmssRandom = new GMSSRandom(this.messDigestOTS);
        int digestSize = this.messDigestOTS.getDigestSize();
        this.mdsize = digestSize;
        int ceil = (int) Math.ceil((digestSize << 3) / this.f1467w);
        this.keysize = ceil + ((int) Math.ceil(getLog((ceil << this.f1467w) + 1) / this.f1467w));
        this.two_power_w = 1 << this.f1467w;
        this.privateKeyOTS = bArr[0];
        this.seed = bArr[1];
        this.concHashs = bArr[2];
        this.leaf = bArr[3];
    }

    private GMSSLeaf(GMSSLeaf gMSSLeaf) {
        this.messDigestOTS = gMSSLeaf.messDigestOTS;
        this.mdsize = gMSSLeaf.mdsize;
        this.keysize = gMSSLeaf.keysize;
        this.gmssRandom = gMSSLeaf.gmssRandom;
        this.leaf = Arrays.clone(gMSSLeaf.leaf);
        this.concHashs = Arrays.clone(gMSSLeaf.concHashs);
        this.f1465i = gMSSLeaf.f1465i;
        this.f1466j = gMSSLeaf.f1466j;
        this.two_power_w = gMSSLeaf.two_power_w;
        this.f1467w = gMSSLeaf.f1467w;
        this.steps = gMSSLeaf.steps;
        this.seed = Arrays.clone(gMSSLeaf.seed);
        this.privateKeyOTS = Arrays.clone(gMSSLeaf.privateKeyOTS);
    }

    private int getLog(int i) {
        int i2 = 1;
        int i3 = 2;
        while (i3 < i) {
            i3 <<= 1;
            i2++;
        }
        return i2;
    }

    private void updateLeafCalc() {
        byte[] bArr = new byte[this.messDigestOTS.getDigestSize()];
        for (int i = 0; i < this.steps + 10000; i++) {
            int i2 = this.f1465i;
            if (i2 == this.keysize && this.f1466j == this.two_power_w - 1) {
                Digest digest = this.messDigestOTS;
                byte[] bArr2 = this.concHashs;
                digest.update(bArr2, 0, bArr2.length);
                byte[] bArr3 = new byte[this.messDigestOTS.getDigestSize()];
                this.leaf = bArr3;
                this.messDigestOTS.doFinal(bArr3, 0);
                return;
            }
            if (i2 == 0 || this.f1466j == this.two_power_w - 1) {
                this.f1465i = i2 + 1;
                this.f1466j = 0;
                this.privateKeyOTS = this.gmssRandom.nextSeed(this.seed);
            } else {
                Digest digest2 = this.messDigestOTS;
                byte[] bArr4 = this.privateKeyOTS;
                digest2.update(bArr4, 0, bArr4.length);
                this.privateKeyOTS = bArr;
                this.messDigestOTS.doFinal(bArr, 0);
                int i3 = this.f1466j + 1;
                this.f1466j = i3;
                if (i3 == this.two_power_w - 1) {
                    byte[] bArr5 = this.privateKeyOTS;
                    byte[] bArr6 = this.concHashs;
                    int i4 = this.mdsize;
                    System.arraycopy(bArr5, 0, bArr6, (this.f1465i - 1) * i4, i4);
                }
            }
        }
        throw new IllegalStateException("unable to updateLeaf in steps: " + this.steps + " " + this.f1465i + " " + this.f1466j);
    }

    public byte[] getLeaf() {
        return Arrays.clone(this.leaf);
    }

    public byte[][] getStatByte() {
        return new byte[][]{this.privateKeyOTS, this.seed, this.concHashs, this.leaf};
    }

    public int[] getStatInt() {
        return new int[]{this.f1465i, this.f1466j, this.steps, this.f1467w};
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void initLeafCalc(byte[] bArr) {
        this.f1465i = 0;
        this.f1466j = 0;
        byte[] bArr2 = new byte[this.mdsize];
        System.arraycopy(bArr, 0, bArr2, 0, this.seed.length);
        this.seed = this.gmssRandom.nextSeed(bArr2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public GMSSLeaf nextLeaf() {
        GMSSLeaf gMSSLeaf = new GMSSLeaf(this);
        gMSSLeaf.updateLeafCalc();
        return gMSSLeaf;
    }

    public String toString() {
        String str = "";
        for (int i = 0; i < 4; i++) {
            str = str + getStatInt()[i] + " ";
        }
        String str2 = str + " " + this.mdsize + " " + this.keysize + " " + this.two_power_w + " ";
        byte[][] statByte = getStatByte();
        for (int i2 = 0; i2 < 4; i2++) {
            str2 = (statByte[i2] != null ? new StringBuilder().append(str2).append(new String(Hex.encode(statByte[i2]))).append(" ") : new StringBuilder().append(str2).append("null ")).toString();
        }
        return str2;
    }
}