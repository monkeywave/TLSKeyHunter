package org.bouncycastle.pqc.crypto.gmss;

import java.security.SecureRandom;
import java.util.Vector;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.gmss.util.GMSSRandom;
import org.bouncycastle.pqc.crypto.gmss.util.WinternitzOTSVerify;
import org.bouncycastle.pqc.crypto.gmss.util.WinternitzOTSignature;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/gmss/GMSSKeyPairGenerator.class */
public class GMSSKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private GMSSRandom gmssRandom;
    private Digest messDigestTree;
    private byte[][] currentSeeds;
    private byte[][] nextNextSeeds;
    private byte[][] currentRootSigs;
    private GMSSDigestProvider digestProvider;
    private int mdLength;
    private int numLayer;
    private boolean initialized = false;
    private GMSSParameters gmssPS;
    private int[] heightOfTrees;
    private int[] otsIndex;

    /* renamed from: K */
    private int[] f813K;
    private GMSSKeyGenerationParameters gmssParams;
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.3";

    public GMSSKeyPairGenerator(GMSSDigestProvider gMSSDigestProvider) {
        this.digestProvider = gMSSDigestProvider;
        this.messDigestTree = gMSSDigestProvider.get();
        this.mdLength = this.messDigestTree.getDigestSize();
        this.gmssRandom = new GMSSRandom(this.messDigestTree);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v11, types: [org.bouncycastle.pqc.crypto.gmss.Treehash[], org.bouncycastle.pqc.crypto.gmss.Treehash[][]] */
    /* JADX WARN: Type inference failed for: r0v15, types: [org.bouncycastle.pqc.crypto.gmss.Treehash[], org.bouncycastle.pqc.crypto.gmss.Treehash[][]] */
    /* JADX WARN: Type inference failed for: r0v25, types: [java.util.Vector[], java.util.Vector[][]] */
    /* JADX WARN: Type inference failed for: r0v29, types: [java.util.Vector[], java.util.Vector[][]] */
    /* JADX WARN: Type inference failed for: r0v4, types: [byte[][], byte[][][]] */
    /* JADX WARN: Type inference failed for: r0v8, types: [byte[][], byte[][][]] */
    private AsymmetricCipherKeyPair genKeyPair() {
        if (!this.initialized) {
            initializeDefault();
        }
        ?? r0 = new byte[this.numLayer];
        ?? r02 = new byte[this.numLayer - 1];
        ?? r03 = new Treehash[this.numLayer];
        ?? r04 = new Treehash[this.numLayer - 1];
        Vector[] vectorArr = new Vector[this.numLayer];
        Vector[] vectorArr2 = new Vector[this.numLayer - 1];
        ?? r05 = new Vector[this.numLayer];
        ?? r06 = new Vector[this.numLayer - 1];
        for (int i = 0; i < this.numLayer; i++) {
            r0[i] = new byte[this.heightOfTrees[i]][this.mdLength];
            r03[i] = new Treehash[this.heightOfTrees[i] - this.f813K[i]];
            if (i > 0) {
                r02[i - 1] = new byte[this.heightOfTrees[i]][this.mdLength];
                r04[i - 1] = new Treehash[this.heightOfTrees[i] - this.f813K[i]];
            }
            vectorArr[i] = new Vector();
            if (i > 0) {
                vectorArr2[i - 1] = new Vector();
            }
        }
        byte[][] bArr = new byte[this.numLayer][this.mdLength];
        byte[][] bArr2 = new byte[this.numLayer - 1][this.mdLength];
        byte[][] bArr3 = new byte[this.numLayer][this.mdLength];
        for (int i2 = 0; i2 < this.numLayer; i2++) {
            System.arraycopy(this.currentSeeds[i2], 0, bArr3[i2], 0, this.mdLength);
        }
        this.currentRootSigs = new byte[this.numLayer - 1][this.mdLength];
        int i3 = this.numLayer - 1;
        while (i3 >= 0) {
            GMSSRootCalc generateCurrentAuthpathAndRoot = i3 == this.numLayer - 1 ? generateCurrentAuthpathAndRoot(null, vectorArr[i3], bArr3[i3], i3) : generateCurrentAuthpathAndRoot(bArr[i3 + 1], vectorArr[i3], bArr3[i3], i3);
            for (int i4 = 0; i4 < this.heightOfTrees[i3]; i4++) {
                System.arraycopy(generateCurrentAuthpathAndRoot.getAuthPath()[i4], 0, r0[i3][i4], 0, this.mdLength);
            }
            r05[i3] = generateCurrentAuthpathAndRoot.getRetain();
            r03[i3] = generateCurrentAuthpathAndRoot.getTreehash();
            System.arraycopy(generateCurrentAuthpathAndRoot.getRoot(), 0, bArr[i3], 0, this.mdLength);
            i3--;
        }
        for (int i5 = this.numLayer - 2; i5 >= 0; i5--) {
            GMSSRootCalc generateNextAuthpathAndRoot = generateNextAuthpathAndRoot(vectorArr2[i5], bArr3[i5 + 1], i5 + 1);
            for (int i6 = 0; i6 < this.heightOfTrees[i5 + 1]; i6++) {
                System.arraycopy(generateNextAuthpathAndRoot.getAuthPath()[i6], 0, r02[i5][i6], 0, this.mdLength);
            }
            r06[i5] = generateNextAuthpathAndRoot.getRetain();
            r04[i5] = generateNextAuthpathAndRoot.getTreehash();
            System.arraycopy(generateNextAuthpathAndRoot.getRoot(), 0, bArr2[i5], 0, this.mdLength);
            System.arraycopy(bArr3[i5 + 1], 0, this.nextNextSeeds[i5], 0, this.mdLength);
        }
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new GMSSPublicKeyParameters(bArr[0], this.gmssPS), (AsymmetricKeyParameter) new GMSSPrivateKeyParameters(this.currentSeeds, this.nextNextSeeds, r0, r02, r03, r04, vectorArr, vectorArr2, r05, r06, bArr2, this.currentRootSigs, this.gmssPS, this.digestProvider));
    }

    private GMSSRootCalc generateCurrentAuthpathAndRoot(byte[] bArr, Vector vector, byte[] bArr2, int i) {
        byte[] Verify;
        byte[] bArr3 = new byte[this.mdLength];
        byte[] bArr4 = new byte[this.mdLength];
        byte[] nextSeed = this.gmssRandom.nextSeed(bArr2);
        GMSSRootCalc gMSSRootCalc = new GMSSRootCalc(this.heightOfTrees[i], this.f813K[i], this.digestProvider);
        gMSSRootCalc.initialize(vector);
        if (i == this.numLayer - 1) {
            Verify = new WinternitzOTSignature(nextSeed, this.digestProvider.get(), this.otsIndex[i]).getPublicKey();
        } else {
            this.currentRootSigs[i] = new WinternitzOTSignature(nextSeed, this.digestProvider.get(), this.otsIndex[i]).getSignature(bArr);
            Verify = new WinternitzOTSVerify(this.digestProvider.get(), this.otsIndex[i]).Verify(bArr, this.currentRootSigs[i]);
        }
        gMSSRootCalc.update(Verify);
        int i2 = 3;
        int i3 = 0;
        for (int i4 = 1; i4 < (1 << this.heightOfTrees[i]); i4++) {
            if (i4 == i2 && i3 < this.heightOfTrees[i] - this.f813K[i]) {
                gMSSRootCalc.initializeTreehashSeed(bArr2, i3);
                i2 *= 2;
                i3++;
            }
            gMSSRootCalc.update(new WinternitzOTSignature(this.gmssRandom.nextSeed(bArr2), this.digestProvider.get(), this.otsIndex[i]).getPublicKey());
        }
        if (gMSSRootCalc.wasFinished()) {
            return gMSSRootCalc;
        }
        System.err.println("Baum noch nicht fertig konstruiert!!!");
        return null;
    }

    private GMSSRootCalc generateNextAuthpathAndRoot(Vector vector, byte[] bArr, int i) {
        byte[] bArr2 = new byte[this.numLayer];
        GMSSRootCalc gMSSRootCalc = new GMSSRootCalc(this.heightOfTrees[i], this.f813K[i], this.digestProvider);
        gMSSRootCalc.initialize(vector);
        int i2 = 3;
        int i3 = 0;
        for (int i4 = 0; i4 < (1 << this.heightOfTrees[i]); i4++) {
            if (i4 == i2 && i3 < this.heightOfTrees[i] - this.f813K[i]) {
                gMSSRootCalc.initializeTreehashSeed(bArr, i3);
                i2 *= 2;
                i3++;
            }
            gMSSRootCalc.update(new WinternitzOTSignature(this.gmssRandom.nextSeed(bArr), this.digestProvider.get(), this.otsIndex[i]).getPublicKey());
        }
        if (gMSSRootCalc.wasFinished()) {
            return gMSSRootCalc;
        }
        System.err.println("N�chster Baum noch nicht fertig konstruiert!!!");
        return null;
    }

    public void initialize(int i, SecureRandom secureRandom) {
        GMSSKeyGenerationParameters gMSSKeyGenerationParameters;
        if (i <= 10) {
            int[] iArr = {10};
            gMSSKeyGenerationParameters = new GMSSKeyGenerationParameters(secureRandom, new GMSSParameters(iArr.length, iArr, new int[]{3}, new int[]{2}));
        } else if (i <= 20) {
            int[] iArr2 = {10, 10};
            gMSSKeyGenerationParameters = new GMSSKeyGenerationParameters(secureRandom, new GMSSParameters(iArr2.length, iArr2, new int[]{5, 4}, new int[]{2, 2}));
        } else {
            int[] iArr3 = {10, 10, 10, 10};
            gMSSKeyGenerationParameters = new GMSSKeyGenerationParameters(secureRandom, new GMSSParameters(iArr3.length, iArr3, new int[]{9, 9, 9, 3}, new int[]{2, 2, 2, 2}));
        }
        initialize(gMSSKeyGenerationParameters);
    }

    public void initialize(KeyGenerationParameters keyGenerationParameters) {
        this.gmssParams = (GMSSKeyGenerationParameters) keyGenerationParameters;
        this.gmssPS = new GMSSParameters(this.gmssParams.getParameters().getNumOfLayers(), this.gmssParams.getParameters().getHeightOfTrees(), this.gmssParams.getParameters().getWinternitzParameter(), this.gmssParams.getParameters().getK());
        this.numLayer = this.gmssPS.getNumOfLayers();
        this.heightOfTrees = this.gmssPS.getHeightOfTrees();
        this.otsIndex = this.gmssPS.getWinternitzParameter();
        this.f813K = this.gmssPS.getK();
        this.currentSeeds = new byte[this.numLayer][this.mdLength];
        this.nextNextSeeds = new byte[this.numLayer - 1][this.mdLength];
        SecureRandom random = keyGenerationParameters.getRandom();
        for (int i = 0; i < this.numLayer; i++) {
            random.nextBytes(this.currentSeeds[i]);
            this.gmssRandom.nextSeed(this.currentSeeds[i]);
        }
        this.initialized = true;
    }

    private void initializeDefault() {
        int[] iArr = {10, 10, 10, 10};
        initialize(new GMSSKeyGenerationParameters(null, new GMSSParameters(iArr.length, iArr, new int[]{3, 3, 3, 3}, new int[]{2, 2, 2, 2})));
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        initialize(keyGenerationParameters);
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        return genKeyPair();
    }
}