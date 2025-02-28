package org.bouncycastle.pqc.crypto.xmss;

import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.pqc.crypto.xmss.OTSHashAddress;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
final class WOTSPlus {
    private final KeyedHashFunctions khf;
    private final WOTSPlusParameters params;
    private byte[] publicSeed;
    private byte[] secretKeySeed;

    /* JADX INFO: Access modifiers changed from: package-private */
    public WOTSPlus(WOTSPlusParameters wOTSPlusParameters) {
        if (wOTSPlusParameters == null) {
            throw new NullPointerException("params == null");
        }
        this.params = wOTSPlusParameters;
        int treeDigestSize = wOTSPlusParameters.getTreeDigestSize();
        this.khf = new KeyedHashFunctions(wOTSPlusParameters.getTreeDigest(), treeDigestSize);
        this.secretKeySeed = new byte[treeDigestSize];
        this.publicSeed = new byte[treeDigestSize];
    }

    private byte[] chain(byte[] bArr, int i, int i2, OTSHashAddress oTSHashAddress) {
        int treeDigestSize = this.params.getTreeDigestSize();
        if (bArr != null) {
            if (bArr.length == treeDigestSize) {
                if (oTSHashAddress != null) {
                    if (oTSHashAddress.toByteArray() != null) {
                        int i3 = i + i2;
                        if (i3 <= this.params.getWinternitzParameter() - 1) {
                            if (i2 == 0) {
                                return bArr;
                            }
                            byte[] chain = chain(bArr, i, i2 - 1, oTSHashAddress);
                            OTSHashAddress oTSHashAddress2 = (OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(oTSHashAddress.getLayerAddress()).withTreeAddress(oTSHashAddress.getTreeAddress()).withOTSAddress(oTSHashAddress.getOTSAddress()).withChainAddress(oTSHashAddress.getChainAddress()).withHashAddress(i3 - 1).withKeyAndMask(0).build();
                            byte[] PRF = this.khf.PRF(this.publicSeed, oTSHashAddress2.toByteArray());
                            byte[] PRF2 = this.khf.PRF(this.publicSeed, ((OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(oTSHashAddress2.getLayerAddress()).withTreeAddress(oTSHashAddress2.getTreeAddress()).withOTSAddress(oTSHashAddress2.getOTSAddress()).withChainAddress(oTSHashAddress2.getChainAddress()).withHashAddress(oTSHashAddress2.getHashAddress()).withKeyAndMask(1).build()).toByteArray());
                            byte[] bArr2 = new byte[treeDigestSize];
                            for (int i4 = 0; i4 < treeDigestSize; i4++) {
                                bArr2[i4] = (byte) (chain[i4] ^ PRF2[i4]);
                            }
                            return this.khf.m11F(PRF, bArr2);
                        }
                        throw new IllegalArgumentException("max chain length must not be greater than w");
                    }
                    throw new NullPointerException("otsHashAddress byte array == null");
                }
                throw new NullPointerException("otsHashAddress == null");
            }
            throw new IllegalArgumentException("startHash needs to be " + treeDigestSize + "bytes");
        }
        throw new NullPointerException("startHash == null");
    }

    private List<Integer> convertToBaseW(byte[] bArr, int i, int i2) {
        if (bArr != null) {
            if (i == 4 || i == 16) {
                int log2 = XMSSUtil.log2(i);
                if (i2 <= (bArr.length * 8) / log2) {
                    ArrayList arrayList = new ArrayList();
                    for (int i3 : bArr) {
                        for (int i4 = 8 - log2; i4 >= 0; i4 -= log2) {
                            arrayList.add(Integer.valueOf((i3 >> i4) & (i - 1)));
                            if (arrayList.size() == i2) {
                                return arrayList;
                            }
                        }
                    }
                    return arrayList;
                }
                throw new IllegalArgumentException("outLength too big");
            }
            throw new IllegalArgumentException("w needs to be 4 or 16");
        }
        throw new NullPointerException("msg == null");
    }

    private byte[] expandSecretKeySeed(int i) {
        if (i < 0 || i >= this.params.getLen()) {
            throw new IllegalArgumentException("index out of bounds");
        }
        return this.khf.PRF(this.secretKeySeed, XMSSUtil.toBytesBigEndian(i, 32));
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public KeyedHashFunctions getKhf() {
        return this.khf;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public WOTSPlusParameters getParams() {
        return this.params;
    }

    protected WOTSPlusPrivateKeyParameters getPrivateKey() {
        int len = this.params.getLen();
        byte[][] bArr = new byte[len];
        for (int i = 0; i < len; i++) {
            bArr[i] = expandSecretKeySeed(i);
        }
        return new WOTSPlusPrivateKeyParameters(this.params, bArr);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public WOTSPlusPublicKeyParameters getPublicKey(OTSHashAddress oTSHashAddress) {
        if (oTSHashAddress != null) {
            byte[][] bArr = new byte[this.params.getLen()];
            for (int i = 0; i < this.params.getLen(); i++) {
                oTSHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(oTSHashAddress.getLayerAddress()).withTreeAddress(oTSHashAddress.getTreeAddress()).withOTSAddress(oTSHashAddress.getOTSAddress()).withChainAddress(i).withHashAddress(oTSHashAddress.getHashAddress()).withKeyAndMask(oTSHashAddress.getKeyAndMask()).build();
                bArr[i] = chain(expandSecretKeySeed(i), 0, this.params.getWinternitzParameter() - 1, oTSHashAddress);
            }
            return new WOTSPlusPublicKeyParameters(this.params, bArr);
        }
        throw new NullPointerException("otsHashAddress == null");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public WOTSPlusPublicKeyParameters getPublicKeyFromSignature(byte[] bArr, WOTSPlusSignature wOTSPlusSignature, OTSHashAddress oTSHashAddress) {
        if (bArr != null) {
            if (bArr.length == this.params.getTreeDigestSize()) {
                if (wOTSPlusSignature != null) {
                    if (oTSHashAddress != null) {
                        List<Integer> convertToBaseW = convertToBaseW(bArr, this.params.getWinternitzParameter(), this.params.getLen1());
                        int i = 0;
                        for (int i2 = 0; i2 < this.params.getLen1(); i2++) {
                            i += (this.params.getWinternitzParameter() - 1) - convertToBaseW.get(i2).intValue();
                        }
                        convertToBaseW.addAll(convertToBaseW(XMSSUtil.toBytesBigEndian(i << (8 - ((this.params.getLen2() * XMSSUtil.log2(this.params.getWinternitzParameter())) % 8)), (int) Math.ceil((this.params.getLen2() * XMSSUtil.log2(this.params.getWinternitzParameter())) / 8.0d)), this.params.getWinternitzParameter(), this.params.getLen2()));
                        byte[][] bArr2 = new byte[this.params.getLen()];
                        for (int i3 = 0; i3 < this.params.getLen(); i3++) {
                            oTSHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(oTSHashAddress.getLayerAddress()).withTreeAddress(oTSHashAddress.getTreeAddress()).withOTSAddress(oTSHashAddress.getOTSAddress()).withChainAddress(i3).withHashAddress(oTSHashAddress.getHashAddress()).withKeyAndMask(oTSHashAddress.getKeyAndMask()).build();
                            bArr2[i3] = chain(wOTSPlusSignature.toByteArray()[i3], convertToBaseW.get(i3).intValue(), (this.params.getWinternitzParameter() - 1) - convertToBaseW.get(i3).intValue(), oTSHashAddress);
                        }
                        return new WOTSPlusPublicKeyParameters(this.params, bArr2);
                    }
                    throw new NullPointerException("otsHashAddress == null");
                }
                throw new NullPointerException("signature == null");
            }
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }
        throw new NullPointerException("messageDigest == null");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public byte[] getPublicSeed() {
        return Arrays.clone(this.publicSeed);
    }

    protected byte[] getSecretKeySeed() {
        return Arrays.clone(this.secretKeySeed);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public byte[] getWOTSPlusSecretKey(byte[] bArr, OTSHashAddress oTSHashAddress) {
        return this.khf.PRF(bArr, ((OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(oTSHashAddress.getLayerAddress()).withTreeAddress(oTSHashAddress.getTreeAddress()).withOTSAddress(oTSHashAddress.getOTSAddress()).build()).toByteArray());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void importKeys(byte[] bArr, byte[] bArr2) {
        if (bArr == null) {
            throw new NullPointerException("secretKeySeed == null");
        }
        if (bArr.length != this.params.getTreeDigestSize()) {
            throw new IllegalArgumentException("size of secretKeySeed needs to be equal to size of digest");
        }
        if (bArr2 == null) {
            throw new NullPointerException("publicSeed == null");
        }
        if (bArr2.length != this.params.getTreeDigestSize()) {
            throw new IllegalArgumentException("size of publicSeed needs to be equal to size of digest");
        }
        this.secretKeySeed = bArr;
        this.publicSeed = bArr2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public WOTSPlusSignature sign(byte[] bArr, OTSHashAddress oTSHashAddress) {
        if (bArr != null) {
            if (bArr.length == this.params.getTreeDigestSize()) {
                if (oTSHashAddress != null) {
                    List<Integer> convertToBaseW = convertToBaseW(bArr, this.params.getWinternitzParameter(), this.params.getLen1());
                    int i = 0;
                    for (int i2 = 0; i2 < this.params.getLen1(); i2++) {
                        i += (this.params.getWinternitzParameter() - 1) - convertToBaseW.get(i2).intValue();
                    }
                    convertToBaseW.addAll(convertToBaseW(XMSSUtil.toBytesBigEndian(i << (8 - ((this.params.getLen2() * XMSSUtil.log2(this.params.getWinternitzParameter())) % 8)), (int) Math.ceil((this.params.getLen2() * XMSSUtil.log2(this.params.getWinternitzParameter())) / 8.0d)), this.params.getWinternitzParameter(), this.params.getLen2()));
                    byte[][] bArr2 = new byte[this.params.getLen()];
                    for (int i3 = 0; i3 < this.params.getLen(); i3++) {
                        oTSHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(oTSHashAddress.getLayerAddress()).withTreeAddress(oTSHashAddress.getTreeAddress()).withOTSAddress(oTSHashAddress.getOTSAddress()).withChainAddress(i3).withHashAddress(oTSHashAddress.getHashAddress()).withKeyAndMask(oTSHashAddress.getKeyAndMask()).build();
                        bArr2[i3] = chain(expandSecretKeySeed(i3), 0, convertToBaseW.get(i3).intValue(), oTSHashAddress);
                    }
                    return new WOTSPlusSignature(this.params, bArr2);
                }
                throw new NullPointerException("otsHashAddress == null");
            }
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }
        throw new NullPointerException("messageDigest == null");
    }
}