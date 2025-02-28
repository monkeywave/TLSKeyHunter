package org.bouncycastle.pqc.crypto.gmss;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.gmss.util.GMSSRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/gmss/GMSSLeaf.class */
public class GMSSLeaf {
    private Digest messDigestOTS;
    private int mdsize;
    private int keysize;
    private GMSSRandom gmssRandom;
    private byte[] leaf;
    private byte[] concHashs;

    /* renamed from: i */
    private int f814i;

    /* renamed from: j */
    private int f815j;
    private int two_power_w;

    /* renamed from: w */
    private int f816w;
    private int steps;
    private byte[] seed;
    byte[] privateKeyOTS;

    public GMSSLeaf(Digest digest, byte[][] bArr, int[] iArr) {
        this.f814i = iArr[0];
        this.f815j = iArr[1];
        this.steps = iArr[2];
        this.f816w = iArr[3];
        this.messDigestOTS = digest;
        this.gmssRandom = new GMSSRandom(this.messDigestOTS);
        this.mdsize = this.messDigestOTS.getDigestSize();
        int ceil = (int) Math.ceil((this.mdsize << 3) / this.f816w);
        this.keysize = ceil + ((int) Math.ceil(getLog((ceil << this.f816w) + 1) / this.f816w));
        this.two_power_w = 1 << this.f816w;
        this.privateKeyOTS = bArr[0];
        this.seed = bArr[1];
        this.concHashs = bArr[2];
        this.leaf = bArr[3];
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public GMSSLeaf(Digest digest, int i, int i2) {
        this.f816w = i;
        this.messDigestOTS = digest;
        this.gmssRandom = new GMSSRandom(this.messDigestOTS);
        this.mdsize = this.messDigestOTS.getDigestSize();
        int ceil = (int) Math.ceil((this.mdsize << 3) / i);
        this.keysize = ceil + ((int) Math.ceil(getLog((ceil << i) + 1) / i));
        this.two_power_w = 1 << i;
        this.steps = (int) Math.ceil((((((1 << i) - 1) * this.keysize) + 1) + this.keysize) / i2);
        this.seed = new byte[this.mdsize];
        this.leaf = new byte[this.mdsize];
        this.privateKeyOTS = new byte[this.mdsize];
        this.concHashs = new byte[this.mdsize * this.keysize];
    }

    public GMSSLeaf(Digest digest, int i, int i2, byte[] bArr) {
        this.f816w = i;
        this.messDigestOTS = digest;
        this.gmssRandom = new GMSSRandom(this.messDigestOTS);
        this.mdsize = this.messDigestOTS.getDigestSize();
        int ceil = (int) Math.ceil((this.mdsize << 3) / i);
        this.keysize = ceil + ((int) Math.ceil(getLog((ceil << i) + 1) / i));
        this.two_power_w = 1 << i;
        this.steps = (int) Math.ceil((((((1 << i) - 1) * this.keysize) + 1) + this.keysize) / i2);
        this.seed = new byte[this.mdsize];
        this.leaf = new byte[this.mdsize];
        this.privateKeyOTS = new byte[this.mdsize];
        this.concHashs = new byte[this.mdsize * this.keysize];
        initLeafCalc(bArr);
    }

    private GMSSLeaf(GMSSLeaf gMSSLeaf) {
        this.messDigestOTS = gMSSLeaf.messDigestOTS;
        this.mdsize = gMSSLeaf.mdsize;
        this.keysize = gMSSLeaf.keysize;
        this.gmssRandom = gMSSLeaf.gmssRandom;
        this.leaf = Arrays.clone(gMSSLeaf.leaf);
        this.concHashs = Arrays.clone(gMSSLeaf.concHashs);
        this.f814i = gMSSLeaf.f814i;
        this.f815j = gMSSLeaf.f815j;
        this.two_power_w = gMSSLeaf.two_power_w;
        this.f816w = gMSSLeaf.f816w;
        this.steps = gMSSLeaf.steps;
        this.seed = Arrays.clone(gMSSLeaf.seed);
        this.privateKeyOTS = Arrays.clone(gMSSLeaf.privateKeyOTS);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void initLeafCalc(byte[] bArr) {
        this.f814i = 0;
        this.f815j = 0;
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

    private void updateLeafCalc() {
        byte[] bArr = new byte[this.messDigestOTS.getDigestSize()];
        for (int i = 0; i < this.steps + 10000; i++) {
            if (this.f814i == this.keysize && this.f815j == this.two_power_w - 1) {
                this.messDigestOTS.update(this.concHashs, 0, this.concHashs.length);
                this.leaf = new byte[this.messDigestOTS.getDigestSize()];
                this.messDigestOTS.doFinal(this.leaf, 0);
                return;
            }
            if (this.f814i == 0 || this.f815j == this.two_power_w - 1) {
                this.f814i++;
                this.f815j = 0;
                this.privateKeyOTS = this.gmssRandom.nextSeed(this.seed);
            } else {
                this.messDigestOTS.update(this.privateKeyOTS, 0, this.privateKeyOTS.length);
                this.privateKeyOTS = bArr;
                this.messDigestOTS.doFinal(this.privateKeyOTS, 0);
                this.f815j++;
                if (this.f815j == this.two_power_w - 1) {
                    System.arraycopy(this.privateKeyOTS, 0, this.concHashs, this.mdsize * (this.f814i - 1), this.mdsize);
                }
            }
        }
        throw new IllegalStateException("unable to updateLeaf in steps: " + this.steps + " " + this.f814i + " " + this.f815j);
    }

    public byte[] getLeaf() {
        return Arrays.clone(this.leaf);
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

    /* JADX WARN: Type inference failed for: r0v1, types: [byte[], byte[][]] */
    public byte[][] getStatByte() {
        return new byte[]{this.privateKeyOTS, this.seed, this.concHashs, this.leaf};
    }

    public int[] getStatInt() {
        return new int[]{this.f814i, this.f815j, this.steps, this.f816w};
    }

    public String toString() {
        String str = "";
        for (int i = 0; i < 4; i++) {
            str = str + getStatInt()[i] + " ";
        }
        String str2 = str + " " + this.mdsize + " " + this.keysize + " " + this.two_power_w + " ";
        byte[][] statByte = getStatByte();
        for (int i2 = 0; i2 < 4; i2++) {
            str2 = statByte[i2] != null ? str2 + new String(Hex.encode(statByte[i2])) + " " : str2 + "null ";
        }
        return str2;
    }
}