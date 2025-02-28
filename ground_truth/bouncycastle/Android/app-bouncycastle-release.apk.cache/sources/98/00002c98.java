package org.bouncycastle.pqc.legacy.crypto.gmss;

import java.lang.reflect.Array;
import java.util.Vector;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.legacy.crypto.gmss.util.GMSSRandom;
import org.bouncycastle.pqc.legacy.crypto.gmss.util.WinternitzOTSignature;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class GMSSPrivateKeyParameters extends GMSSKeyParameters {

    /* renamed from: K */
    private int[] f1469K;
    private byte[][][] currentAuthPaths;
    private Vector[][] currentRetain;
    private byte[][] currentRootSig;
    private byte[][] currentSeeds;
    private Vector[] currentStack;
    private Treehash[][] currentTreehash;
    private GMSSDigestProvider digestProvider;
    private GMSSParameters gmssPS;
    private GMSSRandom gmssRandom;
    private int[] heightOfTrees;
    private int[] index;
    private byte[][][] keep;
    private int mdLength;
    private Digest messDigestTrees;
    private int[] minTreehash;
    private byte[][][] nextAuthPaths;
    private GMSSLeaf[] nextNextLeaf;
    private GMSSRootCalc[] nextNextRoot;
    private byte[][] nextNextSeeds;
    private Vector[][] nextRetain;
    private byte[][] nextRoot;
    private GMSSRootSig[] nextRootSig;
    private Vector[] nextStack;
    private Treehash[][] nextTreehash;
    private int numLayer;
    private int[] numLeafs;
    private int[] otsIndex;
    private GMSSLeaf[] upperLeaf;
    private GMSSLeaf[] upperTreehashLeaf;
    private boolean used;

    private GMSSPrivateKeyParameters(GMSSPrivateKeyParameters gMSSPrivateKeyParameters) {
        super(true, gMSSPrivateKeyParameters.getParameters());
        this.used = false;
        this.index = Arrays.clone(gMSSPrivateKeyParameters.index);
        this.currentSeeds = Arrays.clone(gMSSPrivateKeyParameters.currentSeeds);
        this.nextNextSeeds = Arrays.clone(gMSSPrivateKeyParameters.nextNextSeeds);
        this.currentAuthPaths = Arrays.clone(gMSSPrivateKeyParameters.currentAuthPaths);
        this.nextAuthPaths = Arrays.clone(gMSSPrivateKeyParameters.nextAuthPaths);
        this.currentTreehash = gMSSPrivateKeyParameters.currentTreehash;
        this.nextTreehash = gMSSPrivateKeyParameters.nextTreehash;
        this.currentStack = gMSSPrivateKeyParameters.currentStack;
        this.nextStack = gMSSPrivateKeyParameters.nextStack;
        this.currentRetain = gMSSPrivateKeyParameters.currentRetain;
        this.nextRetain = gMSSPrivateKeyParameters.nextRetain;
        this.keep = Arrays.clone(gMSSPrivateKeyParameters.keep);
        this.nextNextLeaf = gMSSPrivateKeyParameters.nextNextLeaf;
        this.upperLeaf = gMSSPrivateKeyParameters.upperLeaf;
        this.upperTreehashLeaf = gMSSPrivateKeyParameters.upperTreehashLeaf;
        this.minTreehash = gMSSPrivateKeyParameters.minTreehash;
        this.gmssPS = gMSSPrivateKeyParameters.gmssPS;
        this.nextRoot = Arrays.clone(gMSSPrivateKeyParameters.nextRoot);
        this.nextNextRoot = gMSSPrivateKeyParameters.nextNextRoot;
        this.currentRootSig = gMSSPrivateKeyParameters.currentRootSig;
        this.nextRootSig = gMSSPrivateKeyParameters.nextRootSig;
        this.digestProvider = gMSSPrivateKeyParameters.digestProvider;
        this.heightOfTrees = gMSSPrivateKeyParameters.heightOfTrees;
        this.otsIndex = gMSSPrivateKeyParameters.otsIndex;
        this.f1469K = gMSSPrivateKeyParameters.f1469K;
        this.numLayer = gMSSPrivateKeyParameters.numLayer;
        this.messDigestTrees = gMSSPrivateKeyParameters.messDigestTrees;
        this.mdLength = gMSSPrivateKeyParameters.mdLength;
        this.gmssRandom = gMSSPrivateKeyParameters.gmssRandom;
        this.numLeafs = gMSSPrivateKeyParameters.numLeafs;
    }

    public GMSSPrivateKeyParameters(int[] iArr, byte[][] bArr, byte[][] bArr2, byte[][][] bArr3, byte[][][] bArr4, byte[][][] bArr5, Treehash[][] treehashArr, Treehash[][] treehashArr2, Vector[] vectorArr, Vector[] vectorArr2, Vector[][] vectorArr3, Vector[][] vectorArr4, GMSSLeaf[] gMSSLeafArr, GMSSLeaf[] gMSSLeafArr2, GMSSLeaf[] gMSSLeafArr3, int[] iArr2, byte[][] bArr6, GMSSRootCalc[] gMSSRootCalcArr, byte[][] bArr7, GMSSRootSig[] gMSSRootSigArr, GMSSParameters gMSSParameters, GMSSDigestProvider gMSSDigestProvider) {
        super(true, gMSSParameters);
        this.used = false;
        Digest digest = gMSSDigestProvider.get();
        this.messDigestTrees = digest;
        this.mdLength = digest.getDigestSize();
        this.gmssPS = gMSSParameters;
        this.otsIndex = gMSSParameters.getWinternitzParameter();
        this.f1469K = gMSSParameters.getK();
        this.heightOfTrees = gMSSParameters.getHeightOfTrees();
        int numOfLayers = this.gmssPS.getNumOfLayers();
        this.numLayer = numOfLayers;
        if (iArr == null) {
            this.index = new int[numOfLayers];
            for (int i = 0; i < this.numLayer; i++) {
                this.index[i] = 0;
            }
        } else {
            this.index = iArr;
        }
        this.currentSeeds = bArr;
        this.nextNextSeeds = bArr2;
        this.currentAuthPaths = Arrays.clone(bArr3);
        this.nextAuthPaths = bArr4;
        int i2 = 2;
        if (bArr5 == null) {
            this.keep = new byte[this.numLayer][];
            int i3 = 0;
            while (i3 < this.numLayer) {
                this.keep[i3] = (byte[][]) Array.newInstance(Byte.TYPE, (int) Math.floor(this.heightOfTrees[i3] / i2), this.mdLength);
                i3++;
                i2 = 2;
            }
        } else {
            this.keep = bArr5;
        }
        if (vectorArr == null) {
            this.currentStack = new Vector[this.numLayer];
            for (int i4 = 0; i4 < this.numLayer; i4++) {
                this.currentStack[i4] = new Vector();
            }
        } else {
            this.currentStack = vectorArr;
        }
        if (vectorArr2 == null) {
            this.nextStack = new Vector[this.numLayer - 1];
            int i5 = 0;
            for (int i6 = 1; i5 < this.numLayer - i6; i6 = 1) {
                this.nextStack[i5] = new Vector();
                i5++;
            }
        } else {
            this.nextStack = vectorArr2;
        }
        this.currentTreehash = treehashArr;
        this.nextTreehash = treehashArr2;
        this.currentRetain = vectorArr3;
        this.nextRetain = vectorArr4;
        this.nextRoot = bArr6;
        this.digestProvider = gMSSDigestProvider;
        if (gMSSRootCalcArr == null) {
            this.nextNextRoot = new GMSSRootCalc[this.numLayer - 1];
            int i7 = 0;
            for (int i8 = 1; i7 < this.numLayer - i8; i8 = 1) {
                int i9 = i7 + 1;
                this.nextNextRoot[i7] = new GMSSRootCalc(this.heightOfTrees[i9], this.f1469K[i9], this.digestProvider);
                i7 = i9;
            }
        } else {
            this.nextNextRoot = gMSSRootCalcArr;
        }
        this.currentRootSig = bArr7;
        this.numLeafs = new int[this.numLayer];
        for (int i10 = 0; i10 < this.numLayer; i10++) {
            this.numLeafs[i10] = 1 << this.heightOfTrees[i10];
        }
        this.gmssRandom = new GMSSRandom(this.messDigestTrees);
        int i11 = this.numLayer;
        if (i11 <= 1) {
            this.nextNextLeaf = new GMSSLeaf[0];
        } else if (gMSSLeafArr == null) {
            this.nextNextLeaf = new GMSSLeaf[i11 - 2];
            int i12 = 0;
            while (i12 < this.numLayer - 2) {
                int i13 = i12 + 1;
                this.nextNextLeaf[i12] = new GMSSLeaf(gMSSDigestProvider.get(), this.otsIndex[i13], this.numLeafs[i12 + 2], this.nextNextSeeds[i12]);
                i12 = i13;
            }
        } else {
            this.nextNextLeaf = gMSSLeafArr;
        }
        if (gMSSLeafArr2 == null) {
            this.upperLeaf = new GMSSLeaf[this.numLayer - 1];
            int i14 = 0;
            for (int i15 = 1; i14 < this.numLayer - i15; i15 = 1) {
                int i16 = i14 + 1;
                this.upperLeaf[i14] = new GMSSLeaf(gMSSDigestProvider.get(), this.otsIndex[i14], this.numLeafs[i16], this.currentSeeds[i14]);
                i14 = i16;
            }
        } else {
            this.upperLeaf = gMSSLeafArr2;
        }
        if (gMSSLeafArr3 == null) {
            this.upperTreehashLeaf = new GMSSLeaf[this.numLayer - 1];
            int i17 = 0;
            for (int i18 = 1; i17 < this.numLayer - i18; i18 = 1) {
                int i19 = i17 + 1;
                this.upperTreehashLeaf[i17] = new GMSSLeaf(gMSSDigestProvider.get(), this.otsIndex[i17], this.numLeafs[i19]);
                i17 = i19;
            }
        } else {
            this.upperTreehashLeaf = gMSSLeafArr3;
        }
        if (iArr2 == null) {
            this.minTreehash = new int[this.numLayer - 1];
            int i20 = 0;
            for (int i21 = 1; i20 < this.numLayer - i21; i21 = 1) {
                this.minTreehash[i20] = -1;
                i20++;
            }
        } else {
            this.minTreehash = iArr2;
        }
        int i22 = this.mdLength;
        byte[] bArr8 = new byte[i22];
        byte[] bArr9 = new byte[i22];
        if (gMSSRootSigArr != null) {
            this.nextRootSig = gMSSRootSigArr;
            return;
        }
        this.nextRootSig = new GMSSRootSig[this.numLayer - 1];
        int i23 = 0;
        while (i23 < this.numLayer - 1) {
            System.arraycopy(bArr[i23], 0, bArr8, 0, this.mdLength);
            this.gmssRandom.nextSeed(bArr8);
            byte[] nextSeed = this.gmssRandom.nextSeed(bArr8);
            int i24 = i23 + 1;
            this.nextRootSig[i23] = new GMSSRootSig(gMSSDigestProvider.get(), this.otsIndex[i23], this.heightOfTrees[i24]);
            this.nextRootSig[i23].initSign(nextSeed, bArr6[i23]);
            i23 = i24;
        }
    }

    public GMSSPrivateKeyParameters(byte[][] bArr, byte[][] bArr2, byte[][][] bArr3, byte[][][] bArr4, Treehash[][] treehashArr, Treehash[][] treehashArr2, Vector[] vectorArr, Vector[] vectorArr2, Vector[][] vectorArr3, Vector[][] vectorArr4, byte[][] bArr5, byte[][] bArr6, GMSSParameters gMSSParameters, GMSSDigestProvider gMSSDigestProvider) {
        this(null, bArr, bArr2, bArr3, bArr4, null, treehashArr, treehashArr2, vectorArr, vectorArr2, vectorArr3, vectorArr4, null, null, null, null, bArr5, null, bArr6, null, gMSSParameters, gMSSDigestProvider);
    }

    private void computeAuthPaths(int i) {
        int i2;
        int i3;
        byte[] bArr;
        int i4 = this.index[i];
        int i5 = this.heightOfTrees[i];
        int i6 = this.f1469K[i];
        int i7 = 0;
        while (true) {
            i2 = i5 - i6;
            if (i7 >= i2) {
                break;
            }
            this.currentTreehash[i][i7].updateNextSeed(this.gmssRandom);
            i7++;
        }
        int heightOfPhi = heightOfPhi(i4);
        byte[] bArr2 = new byte[this.mdLength];
        byte[] nextSeed = this.gmssRandom.nextSeed(this.currentSeeds[i]);
        int i8 = (i4 >>> (heightOfPhi + 1)) & 1;
        int i9 = this.mdLength;
        byte[] bArr3 = new byte[i9];
        int i10 = i5 - 1;
        if (heightOfPhi < i10 && i8 == 0) {
            System.arraycopy(this.currentAuthPaths[i][heightOfPhi], 0, bArr3, 0, i9);
        }
        int i11 = this.mdLength;
        byte[] bArr4 = new byte[i11];
        if (heightOfPhi == 0) {
            if (i == this.numLayer - 1) {
                bArr = new WinternitzOTSignature(nextSeed, this.digestProvider.get(), this.otsIndex[i]).getPublicKey();
            } else {
                byte[] bArr5 = new byte[i11];
                System.arraycopy(this.currentSeeds[i], 0, bArr5, 0, i11);
                this.gmssRandom.nextSeed(bArr5);
                byte[] leaf = this.upperLeaf[i].getLeaf();
                this.upperLeaf[i].initLeafCalc(bArr5);
                bArr = leaf;
            }
            System.arraycopy(bArr, 0, this.currentAuthPaths[i][0], 0, this.mdLength);
        } else {
            int i12 = i11 << 1;
            byte[] bArr6 = new byte[i12];
            System.arraycopy(this.currentAuthPaths[i][heightOfPhi - 1], 0, bArr6, 0, i11);
            byte[] bArr7 = this.keep[i][(int) Math.floor(i3 / 2)];
            int i13 = this.mdLength;
            System.arraycopy(bArr7, 0, bArr6, i13, i13);
            this.messDigestTrees.update(bArr6, 0, i12);
            this.currentAuthPaths[i][heightOfPhi] = new byte[this.messDigestTrees.getDigestSize()];
            this.messDigestTrees.doFinal(this.currentAuthPaths[i][heightOfPhi], 0);
            for (int i14 = 0; i14 < heightOfPhi; i14++) {
                if (i14 < i2) {
                    if (this.currentTreehash[i][i14].wasFinished()) {
                        System.arraycopy(this.currentTreehash[i][i14].getFirstNode(), 0, this.currentAuthPaths[i][i14], 0, this.mdLength);
                        this.currentTreehash[i][i14].destroy();
                    } else {
                        System.err.println("Treehash (" + i + "," + i14 + ") not finished when needed in AuthPathComputation");
                    }
                }
                if (i14 < i10 && i14 >= i2) {
                    int i15 = i14 - i2;
                    if (this.currentRetain[i][i15].size() > 0) {
                        System.arraycopy(this.currentRetain[i][i15].lastElement(), 0, this.currentAuthPaths[i][i14], 0, this.mdLength);
                        Vector vector = this.currentRetain[i][i15];
                        vector.removeElementAt(vector.size() - 1);
                    }
                }
                if (i14 < i2 && ((1 << i14) * 3) + i4 < this.numLeafs[i]) {
                    this.currentTreehash[i][i14].initialize();
                }
            }
        }
        if (heightOfPhi < i10 && i8 == 0) {
            System.arraycopy(bArr3, 0, this.keep[i][(int) Math.floor(heightOfPhi / 2)], 0, this.mdLength);
        }
        if (i != this.numLayer - 1) {
            this.minTreehash[i] = getMinTreehashIndex(i);
            return;
        }
        for (int i16 = 1; i16 <= i2 / 2; i16++) {
            int minTreehashIndex = getMinTreehashIndex(i);
            if (minTreehashIndex >= 0) {
                try {
                    byte[] bArr8 = new byte[this.mdLength];
                    System.arraycopy(this.currentTreehash[i][minTreehashIndex].getSeedActive(), 0, bArr8, 0, this.mdLength);
                    this.currentTreehash[i][minTreehashIndex].update(this.gmssRandom, new WinternitzOTSignature(this.gmssRandom.nextSeed(bArr8), this.digestProvider.get(), this.otsIndex[i]).getPublicKey());
                } catch (Exception e) {
                    System.out.println(e);
                }
            }
        }
    }

    private int getMinTreehashIndex(int i) {
        int i2 = -1;
        for (int i3 = 0; i3 < this.heightOfTrees[i] - this.f1469K[i]; i3++) {
            if (this.currentTreehash[i][i3].wasInitialized() && !this.currentTreehash[i][i3].wasFinished() && (i2 == -1 || this.currentTreehash[i][i3].getLowestNodeHeight() < this.currentTreehash[i][i2].getLowestNodeHeight())) {
                i2 = i3;
            }
        }
        return i2;
    }

    private int heightOfPhi(int i) {
        if (i == 0) {
            return -1;
        }
        int i2 = 0;
        int i3 = 1;
        while (i % i3 == 0) {
            i3 *= 2;
            i2++;
        }
        return i2 - 1;
    }

    private void nextKey(int i) {
        int i2 = this.numLayer;
        if (i == i2 - 1) {
            int[] iArr = this.index;
            iArr[i] = iArr[i] + 1;
        }
        if (this.index[i] != this.numLeafs[i]) {
            updateKey(i);
        } else if (i2 != 1) {
            nextTree(i);
            this.index[i] = 0;
        }
    }

    private void nextTree(int i) {
        if (i > 0) {
            int[] iArr = this.index;
            int i2 = i - 1;
            iArr[i2] = iArr[i2] + 1;
            int i3 = i;
            boolean z = true;
            do {
                i3--;
                if (this.index[i3] < this.numLeafs[i3]) {
                    z = false;
                }
                if (!z) {
                    break;
                }
            } while (i3 > 0);
            if (z) {
                return;
            }
            this.gmssRandom.nextSeed(this.currentSeeds[i]);
            this.nextRootSig[i2].updateSign();
            if (i > 1) {
                GMSSLeaf[] gMSSLeafArr = this.nextNextLeaf;
                int i4 = i - 2;
                gMSSLeafArr[i4] = gMSSLeafArr[i4].nextLeaf();
            }
            GMSSLeaf[] gMSSLeafArr2 = this.upperLeaf;
            gMSSLeafArr2[i2] = gMSSLeafArr2[i2].nextLeaf();
            if (this.minTreehash[i2] >= 0) {
                GMSSLeaf[] gMSSLeafArr3 = this.upperTreehashLeaf;
                gMSSLeafArr3[i2] = gMSSLeafArr3[i2].nextLeaf();
                try {
                    this.currentTreehash[i2][this.minTreehash[i2]].update(this.gmssRandom, this.upperTreehashLeaf[i2].getLeaf());
                    this.currentTreehash[i2][this.minTreehash[i2]].wasFinished();
                } catch (Exception e) {
                    System.out.println(e);
                }
            }
            updateNextNextAuthRoot(i);
            this.currentRootSig[i2] = this.nextRootSig[i2].getSig();
            for (int i5 = 0; i5 < this.heightOfTrees[i] - this.f1469K[i]; i5++) {
                Treehash[] treehashArr = this.currentTreehash[i];
                Treehash[][] treehashArr2 = this.nextTreehash;
                treehashArr[i5] = treehashArr2[i2][i5];
                treehashArr2[i2][i5] = this.nextNextRoot[i2].getTreehash()[i5];
            }
            for (int i6 = 0; i6 < this.heightOfTrees[i]; i6++) {
                System.arraycopy(this.nextAuthPaths[i2][i6], 0, this.currentAuthPaths[i][i6], 0, this.mdLength);
                System.arraycopy(this.nextNextRoot[i2].getAuthPath()[i6], 0, this.nextAuthPaths[i2][i6], 0, this.mdLength);
            }
            for (int i7 = 0; i7 < this.f1469K[i] - 1; i7++) {
                Vector[] vectorArr = this.currentRetain[i];
                Vector[][] vectorArr2 = this.nextRetain;
                vectorArr[i7] = vectorArr2[i2][i7];
                vectorArr2[i2][i7] = this.nextNextRoot[i2].getRetain()[i7];
            }
            Vector[] vectorArr3 = this.currentStack;
            Vector[] vectorArr4 = this.nextStack;
            vectorArr3[i] = vectorArr4[i2];
            vectorArr4[i2] = this.nextNextRoot[i2].getStack();
            this.nextRoot[i2] = this.nextNextRoot[i2].getRoot();
            int i8 = this.mdLength;
            byte[] bArr = new byte[i8];
            byte[] bArr2 = new byte[i8];
            System.arraycopy(this.currentSeeds[i2], 0, bArr2, 0, i8);
            this.gmssRandom.nextSeed(bArr2);
            this.gmssRandom.nextSeed(bArr2);
            this.nextRootSig[i2].initSign(this.gmssRandom.nextSeed(bArr2), this.nextRoot[i2]);
            nextKey(i2);
        }
    }

    private void updateKey(int i) {
        computeAuthPaths(i);
        if (i > 0) {
            if (i > 1) {
                GMSSLeaf[] gMSSLeafArr = this.nextNextLeaf;
                int i2 = i - 2;
                gMSSLeafArr[i2] = gMSSLeafArr[i2].nextLeaf();
            }
            GMSSLeaf[] gMSSLeafArr2 = this.upperLeaf;
            int i3 = i - 1;
            gMSSLeafArr2[i3] = gMSSLeafArr2[i3].nextLeaf();
            int floor = (int) Math.floor((getNumLeafs(i) * 2) / (this.heightOfTrees[i3] - this.f1469K[i3]));
            int i4 = this.index[i];
            if (i4 % floor == 1) {
                if (i4 > 1 && this.minTreehash[i3] >= 0) {
                    try {
                        this.currentTreehash[i3][this.minTreehash[i3]].update(this.gmssRandom, this.upperTreehashLeaf[i3].getLeaf());
                        this.currentTreehash[i3][this.minTreehash[i3]].wasFinished();
                    } catch (Exception e) {
                        System.out.println(e);
                    }
                }
                this.minTreehash[i3] = getMinTreehashIndex(i3);
                int i5 = this.minTreehash[i3];
                if (i5 >= 0) {
                    this.upperTreehashLeaf[i3] = new GMSSLeaf(this.digestProvider.get(), this.otsIndex[i3], floor, this.currentTreehash[i3][i5].getSeedActive());
                    GMSSLeaf[] gMSSLeafArr3 = this.upperTreehashLeaf;
                    gMSSLeafArr3[i3] = gMSSLeafArr3[i3].nextLeaf();
                }
            } else if (this.minTreehash[i3] >= 0) {
                GMSSLeaf[] gMSSLeafArr4 = this.upperTreehashLeaf;
                gMSSLeafArr4[i3] = gMSSLeafArr4[i3].nextLeaf();
            }
            this.nextRootSig[i3].updateSign();
            if (this.index[i] == 1) {
                this.nextNextRoot[i3].initialize(new Vector());
            }
            updateNextNextAuthRoot(i);
        }
    }

    private void updateNextNextAuthRoot(int i) {
        byte[] bArr = new byte[this.mdLength];
        int i2 = i - 1;
        byte[] nextSeed = this.gmssRandom.nextSeed(this.nextNextSeeds[i2]);
        if (i == this.numLayer - 1) {
            this.nextNextRoot[i2].update(this.nextNextSeeds[i2], new WinternitzOTSignature(nextSeed, this.digestProvider.get(), this.otsIndex[i]).getPublicKey());
            return;
        }
        this.nextNextRoot[i2].update(this.nextNextSeeds[i2], this.nextNextLeaf[i2].getLeaf());
        this.nextNextLeaf[i2].initLeafCalc(this.nextNextSeeds[i2]);
    }

    public byte[][][] getCurrentAuthPaths() {
        return Arrays.clone(this.currentAuthPaths);
    }

    public byte[][] getCurrentSeeds() {
        return Arrays.clone(this.currentSeeds);
    }

    public int getIndex(int i) {
        return this.index[i];
    }

    public int[] getIndex() {
        return this.index;
    }

    public GMSSDigestProvider getName() {
        return this.digestProvider;
    }

    public int getNumLeafs(int i) {
        return this.numLeafs[i];
    }

    public byte[] getSubtreeRootSig(int i) {
        return this.currentRootSig[i];
    }

    public boolean isUsed() {
        return this.used;
    }

    public void markUsed() {
        this.used = true;
    }

    public GMSSPrivateKeyParameters nextKey() {
        GMSSPrivateKeyParameters gMSSPrivateKeyParameters = new GMSSPrivateKeyParameters(this);
        gMSSPrivateKeyParameters.nextKey(this.gmssPS.getNumOfLayers() - 1);
        return gMSSPrivateKeyParameters;
    }
}