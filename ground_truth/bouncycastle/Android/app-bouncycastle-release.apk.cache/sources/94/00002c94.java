package org.bouncycastle.pqc.legacy.crypto.gmss;

import java.lang.reflect.Array;
import java.security.SecureRandom;
import java.util.Vector;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.legacy.crypto.gmss.util.GMSSRandom;
import org.bouncycastle.pqc.legacy.crypto.gmss.util.WinternitzOTSVerify;
import org.bouncycastle.pqc.legacy.crypto.gmss.util.WinternitzOTSignature;

/* loaded from: classes2.dex */
public class GMSSKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.3";

    /* renamed from: K */
    private int[] f1464K;
    private byte[][] currentRootSigs;
    private byte[][] currentSeeds;
    private GMSSDigestProvider digestProvider;
    private GMSSParameters gmssPS;
    private GMSSKeyGenerationParameters gmssParams;
    private GMSSRandom gmssRandom;
    private int[] heightOfTrees;
    private boolean initialized = false;
    private int mdLength;
    private Digest messDigestTree;
    private byte[][] nextNextSeeds;
    private int numLayer;
    private int[] otsIndex;

    public GMSSKeyPairGenerator(GMSSDigestProvider gMSSDigestProvider) {
        this.digestProvider = gMSSDigestProvider;
        Digest digest = gMSSDigestProvider.get();
        this.messDigestTree = digest;
        this.mdLength = digest.getDigestSize();
        this.gmssRandom = new GMSSRandom(this.messDigestTree);
    }

    private AsymmetricCipherKeyPair genKeyPair() {
        int i;
        int i2;
        if (!this.initialized) {
            initializeDefault();
        }
        int i3 = this.numLayer;
        byte[][][] bArr = new byte[i3][];
        byte[][][] bArr2 = new byte[i3 - 1][];
        Treehash[][] treehashArr = new Treehash[i3];
        Treehash[][] treehashArr2 = new Treehash[i3 - 1];
        Vector[] vectorArr = new Vector[i3];
        Vector[] vectorArr2 = new Vector[i3 - 1];
        Vector[][] vectorArr3 = new Vector[i3];
        int i4 = 1;
        Vector[][] vectorArr4 = new Vector[i3 - 1];
        int i5 = 0;
        while (true) {
            i = this.numLayer;
            if (i5 >= i) {
                break;
            }
            bArr[i5] = (byte[][]) Array.newInstance(Byte.TYPE, this.heightOfTrees[i5], this.mdLength);
            int i6 = this.heightOfTrees[i5];
            treehashArr[i5] = new Treehash[i6 - this.f1464K[i5]];
            if (i5 > 0) {
                int i7 = i5 - 1;
                bArr2[i7] = (byte[][]) Array.newInstance(Byte.TYPE, i6, this.mdLength);
                treehashArr2[i7] = new Treehash[this.heightOfTrees[i5] - this.f1464K[i5]];
            }
            vectorArr[i5] = new Vector();
            if (i5 > 0) {
                vectorArr2[i5 - 1] = new Vector();
            }
            i5++;
        }
        byte[][] bArr3 = (byte[][]) Array.newInstance(Byte.TYPE, i, this.mdLength);
        byte[][] bArr4 = (byte[][]) Array.newInstance(Byte.TYPE, this.numLayer - 1, this.mdLength);
        byte[][] bArr5 = (byte[][]) Array.newInstance(Byte.TYPE, this.numLayer, this.mdLength);
        int i8 = 0;
        while (true) {
            i2 = this.numLayer;
            if (i8 >= i2) {
                break;
            }
            System.arraycopy(this.currentSeeds[i8], 0, bArr5[i8], 0, this.mdLength);
            i8++;
            i4 = 1;
        }
        int[] iArr = new int[2];
        iArr[i4] = this.mdLength;
        iArr[0] = i2 - i4;
        this.currentRootSigs = (byte[][]) Array.newInstance(Byte.TYPE, iArr);
        int i9 = this.numLayer - i4;
        while (i9 >= 0) {
            GMSSRootCalc generateCurrentAuthpathAndRoot = i9 == this.numLayer - i4 ? generateCurrentAuthpathAndRoot(null, vectorArr[i9], bArr5[i9], i9) : generateCurrentAuthpathAndRoot(bArr3[i9 + 1], vectorArr[i9], bArr5[i9], i9);
            int i10 = 0;
            while (i10 < this.heightOfTrees[i9]) {
                System.arraycopy(generateCurrentAuthpathAndRoot.getAuthPath()[i10], 0, bArr[i9][i10], 0, this.mdLength);
                i10++;
                vectorArr = vectorArr;
            }
            vectorArr3[i9] = generateCurrentAuthpathAndRoot.getRetain();
            treehashArr[i9] = generateCurrentAuthpathAndRoot.getTreehash();
            System.arraycopy(generateCurrentAuthpathAndRoot.getRoot(), 0, bArr3[i9], 0, this.mdLength);
            i9--;
            vectorArr = vectorArr;
            i4 = 1;
        }
        Vector[] vectorArr5 = vectorArr;
        int i11 = this.numLayer - 2;
        while (i11 >= 0) {
            int i12 = i11 + 1;
            GMSSRootCalc generateNextAuthpathAndRoot = generateNextAuthpathAndRoot(vectorArr2[i11], bArr5[i12], i12);
            int i13 = 0;
            while (i13 < this.heightOfTrees[i12]) {
                System.arraycopy(generateNextAuthpathAndRoot.getAuthPath()[i13], 0, bArr2[i11][i13], 0, this.mdLength);
                i13++;
                vectorArr3 = vectorArr3;
            }
            vectorArr4[i11] = generateNextAuthpathAndRoot.getRetain();
            treehashArr2[i11] = generateNextAuthpathAndRoot.getTreehash();
            System.arraycopy(generateNextAuthpathAndRoot.getRoot(), 0, bArr4[i11], 0, this.mdLength);
            System.arraycopy(bArr5[i12], 0, this.nextNextSeeds[i11], 0, this.mdLength);
            i11--;
            vectorArr3 = vectorArr3;
        }
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new GMSSPublicKeyParameters(bArr3[0], this.gmssPS), (AsymmetricKeyParameter) new GMSSPrivateKeyParameters(this.currentSeeds, this.nextNextSeeds, bArr, bArr2, treehashArr, treehashArr2, vectorArr5, vectorArr2, vectorArr3, vectorArr4, bArr4, this.currentRootSigs, this.gmssPS, this.digestProvider));
    }

    private GMSSRootCalc generateCurrentAuthpathAndRoot(byte[] bArr, Vector vector, byte[] bArr2, int i) {
        byte[] Verify;
        int i2 = this.mdLength;
        byte[] bArr3 = new byte[i2];
        byte[] bArr4 = new byte[i2];
        byte[] nextSeed = this.gmssRandom.nextSeed(bArr2);
        GMSSRootCalc gMSSRootCalc = new GMSSRootCalc(this.heightOfTrees[i], this.f1464K[i], this.digestProvider);
        gMSSRootCalc.initialize(vector);
        if (i == this.numLayer - 1) {
            Verify = new WinternitzOTSignature(nextSeed, this.digestProvider.get(), this.otsIndex[i]).getPublicKey();
        } else {
            this.currentRootSigs[i] = new WinternitzOTSignature(nextSeed, this.digestProvider.get(), this.otsIndex[i]).getSignature(bArr);
            Verify = new WinternitzOTSVerify(this.digestProvider.get(), this.otsIndex[i]).Verify(bArr, this.currentRootSigs[i]);
        }
        gMSSRootCalc.update(Verify);
        int i3 = 3;
        int i4 = 0;
        int i5 = 1;
        while (true) {
            int i6 = this.heightOfTrees[i];
            if (i5 >= (1 << i6)) {
                break;
            }
            if (i5 == i3 && i4 < i6 - this.f1464K[i]) {
                gMSSRootCalc.initializeTreehashSeed(bArr2, i4);
                i3 *= 2;
                i4++;
            }
            gMSSRootCalc.update(new WinternitzOTSignature(this.gmssRandom.nextSeed(bArr2), this.digestProvider.get(), this.otsIndex[i]).getPublicKey());
            i5++;
        }
        if (gMSSRootCalc.wasFinished()) {
            return gMSSRootCalc;
        }
        System.err.println("Baum noch nicht fertig konstruiert!!!");
        return null;
    }

    private GMSSRootCalc generateNextAuthpathAndRoot(Vector vector, byte[] bArr, int i) {
        byte[] bArr2 = new byte[this.numLayer];
        GMSSRootCalc gMSSRootCalc = new GMSSRootCalc(this.heightOfTrees[i], this.f1464K[i], this.digestProvider);
        gMSSRootCalc.initialize(vector);
        int i2 = 3;
        int i3 = 0;
        int i4 = 0;
        while (true) {
            int i5 = this.heightOfTrees[i];
            if (i3 >= (1 << i5)) {
                break;
            }
            if (i3 == i2 && i4 < i5 - this.f1464K[i]) {
                gMSSRootCalc.initializeTreehashSeed(bArr, i4);
                i2 *= 2;
                i4++;
            }
            gMSSRootCalc.update(new WinternitzOTSignature(this.gmssRandom.nextSeed(bArr), this.digestProvider.get(), this.otsIndex[i]).getPublicKey());
            i3++;
        }
        if (gMSSRootCalc.wasFinished()) {
            return gMSSRootCalc;
        }
        System.err.println("N�chster Baum noch nicht fertig konstruiert!!!");
        return null;
    }

    private void initializeDefault() {
        initialize(new GMSSKeyGenerationParameters(null, new GMSSParameters(4, new int[]{10, 10, 10, 10}, new int[]{3, 3, 3, 3}, new int[]{2, 2, 2, 2})));
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        return genKeyPair();
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        initialize(keyGenerationParameters);
    }

    public void initialize(int i, SecureRandom secureRandom) {
        initialize(i <= 10 ? new GMSSKeyGenerationParameters(secureRandom, new GMSSParameters(1, new int[]{10}, new int[]{3}, new int[]{2})) : i <= 20 ? new GMSSKeyGenerationParameters(secureRandom, new GMSSParameters(2, new int[]{10, 10}, new int[]{5, 4}, new int[]{2, 2})) : new GMSSKeyGenerationParameters(secureRandom, new GMSSParameters(4, new int[]{10, 10, 10, 10}, new int[]{9, 9, 9, 3}, new int[]{2, 2, 2, 2})));
    }

    public void initialize(KeyGenerationParameters keyGenerationParameters) {
        this.gmssParams = (GMSSKeyGenerationParameters) keyGenerationParameters;
        GMSSParameters gMSSParameters = new GMSSParameters(this.gmssParams.getParameters().getNumOfLayers(), this.gmssParams.getParameters().getHeightOfTrees(), this.gmssParams.getParameters().getWinternitzParameter(), this.gmssParams.getParameters().getK());
        this.gmssPS = gMSSParameters;
        this.numLayer = gMSSParameters.getNumOfLayers();
        this.heightOfTrees = this.gmssPS.getHeightOfTrees();
        this.otsIndex = this.gmssPS.getWinternitzParameter();
        this.f1464K = this.gmssPS.getK();
        this.currentSeeds = (byte[][]) Array.newInstance(Byte.TYPE, this.numLayer, this.mdLength);
        this.nextNextSeeds = (byte[][]) Array.newInstance(Byte.TYPE, this.numLayer - 1, this.mdLength);
        SecureRandom random = keyGenerationParameters.getRandom();
        for (int i = 0; i < this.numLayer; i++) {
            random.nextBytes(this.currentSeeds[i]);
            this.gmssRandom.nextSeed(this.currentSeeds[i]);
        }
        this.initialized = true;
    }
}