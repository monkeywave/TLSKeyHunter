package org.bouncycastle.pqc.crypto.xmss;

import java.util.List;
import org.bouncycastle.pqc.crypto.xmss.OTSHashAddress;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/xmss/WOTSPlus.class */
final class WOTSPlus {
    private final WOTSPlusParameters params;
    private final KeyedHashFunctions khf;
    private byte[] secretKeySeed;
    private byte[] publicSeed;

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
    /* JADX WARN: Type inference failed for: r0v26, types: [byte[], byte[][]] */
    public WOTSPlusSignature sign(byte[] bArr, OTSHashAddress oTSHashAddress) {
        if (bArr == null) {
            throw new NullPointerException("messageDigest == null");
        }
        if (bArr.length != this.params.getTreeDigestSize()) {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }
        if (oTSHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        }
        List<Integer> convertToBaseW = convertToBaseW(bArr, this.params.getWinternitzParameter(), this.params.getLen1());
        int i = 0;
        for (int i2 = 0; i2 < this.params.getLen1(); i2++) {
            i += (this.params.getWinternitzParameter() - 1) - convertToBaseW.get(i2).intValue();
        }
        convertToBaseW.addAll(convertToBaseW(XMSSUtil.toBytesBigEndian(i << (8 - ((this.params.getLen2() * XMSSUtil.log2(this.params.getWinternitzParameter())) % 8)), (int) Math.ceil((this.params.getLen2() * XMSSUtil.log2(this.params.getWinternitzParameter())) / 8.0d)), this.params.getWinternitzParameter(), this.params.getLen2()));
        ?? r0 = new byte[this.params.getLen()];
        for (int i3 = 0; i3 < this.params.getLen(); i3++) {
            oTSHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(oTSHashAddress.getLayerAddress()).withTreeAddress(oTSHashAddress.getTreeAddress()).withOTSAddress(oTSHashAddress.getOTSAddress()).withChainAddress(i3).withHashAddress(oTSHashAddress.getHashAddress()).withKeyAndMask(oTSHashAddress.getKeyAndMask()).build();
            r0[i3] = chain(expandSecretKeySeed(i3), 0, convertToBaseW.get(i3).intValue(), oTSHashAddress);
        }
        return new WOTSPlusSignature(this.params, r0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Type inference failed for: r0v27, types: [byte[], byte[][]] */
    public WOTSPlusPublicKeyParameters getPublicKeyFromSignature(byte[] bArr, WOTSPlusSignature wOTSPlusSignature, OTSHashAddress oTSHashAddress) {
        if (bArr == null) {
            throw new NullPointerException("messageDigest == null");
        }
        if (bArr.length != this.params.getTreeDigestSize()) {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }
        if (wOTSPlusSignature == null) {
            throw new NullPointerException("signature == null");
        }
        if (oTSHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        }
        List<Integer> convertToBaseW = convertToBaseW(bArr, this.params.getWinternitzParameter(), this.params.getLen1());
        int i = 0;
        for (int i2 = 0; i2 < this.params.getLen1(); i2++) {
            i += (this.params.getWinternitzParameter() - 1) - convertToBaseW.get(i2).intValue();
        }
        convertToBaseW.addAll(convertToBaseW(XMSSUtil.toBytesBigEndian(i << (8 - ((this.params.getLen2() * XMSSUtil.log2(this.params.getWinternitzParameter())) % 8)), (int) Math.ceil((this.params.getLen2() * XMSSUtil.log2(this.params.getWinternitzParameter())) / 8.0d)), this.params.getWinternitzParameter(), this.params.getLen2()));
        ?? r0 = new byte[this.params.getLen()];
        for (int i3 = 0; i3 < this.params.getLen(); i3++) {
            oTSHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(oTSHashAddress.getLayerAddress()).withTreeAddress(oTSHashAddress.getTreeAddress()).withOTSAddress(oTSHashAddress.getOTSAddress()).withChainAddress(i3).withHashAddress(oTSHashAddress.getHashAddress()).withKeyAndMask(oTSHashAddress.getKeyAndMask()).build();
            r0[i3] = chain(wOTSPlusSignature.toByteArray()[i3], convertToBaseW.get(i3).intValue(), (this.params.getWinternitzParameter() - 1) - convertToBaseW.get(i3).intValue(), oTSHashAddress);
        }
        return new WOTSPlusPublicKeyParameters(this.params, r0);
    }

    private byte[] chain(byte[] bArr, int i, int i2, OTSHashAddress oTSHashAddress) {
        int treeDigestSize = this.params.getTreeDigestSize();
        if (bArr == null) {
            throw new NullPointerException("startHash == null");
        }
        if (bArr.length != treeDigestSize) {
            throw new IllegalArgumentException("startHash needs to be " + treeDigestSize + "bytes");
        }
        if (oTSHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        }
        if (oTSHashAddress.toByteArray() == null) {
            throw new NullPointerException("otsHashAddress byte array == null");
        }
        if (i + i2 > this.params.getWinternitzParameter() - 1) {
            throw new IllegalArgumentException("max chain length must not be greater than w");
        }
        if (i2 == 0) {
            return bArr;
        }
        byte[] chain = chain(bArr, i, i2 - 1, oTSHashAddress);
        OTSHashAddress oTSHashAddress2 = (OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(oTSHashAddress.getLayerAddress()).withTreeAddress(oTSHashAddress.getTreeAddress()).withOTSAddress(oTSHashAddress.getOTSAddress()).withChainAddress(oTSHashAddress.getChainAddress()).withHashAddress((i + i2) - 1).withKeyAndMask(0).build();
        byte[] PRF = this.khf.PRF(this.publicSeed, oTSHashAddress2.toByteArray());
        byte[] PRF2 = this.khf.PRF(this.publicSeed, ((OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(oTSHashAddress2.getLayerAddress()).withTreeAddress(oTSHashAddress2.getTreeAddress()).withOTSAddress(oTSHashAddress2.getOTSAddress()).withChainAddress(oTSHashAddress2.getChainAddress()).withHashAddress(oTSHashAddress2.getHashAddress()).withKeyAndMask(1).build()).toByteArray());
        byte[] bArr2 = new byte[treeDigestSize];
        for (int i3 = 0; i3 < treeDigestSize; i3++) {
            bArr2[i3] = (byte) (chain[i3] ^ PRF2[i3]);
        }
        return this.khf.m2F(PRF, bArr2);
    }

    /* JADX WARN: Code restructure failed: missing block: B:27:0x0088, code lost:
        r11 = r11 + 1;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private java.util.List<java.lang.Integer> convertToBaseW(byte[] r6, int r7, int r8) {
        /*
            r5 = this;
            r0 = r6
            if (r0 != 0) goto Le
            java.lang.NullPointerException r0 = new java.lang.NullPointerException
            r1 = r0
            java.lang.String r2 = "msg == null"
            r1.<init>(r2)
            throw r0
        Le:
            r0 = r7
            r1 = 4
            if (r0 == r1) goto L23
            r0 = r7
            r1 = 16
            if (r0 == r1) goto L23
            java.lang.IllegalArgumentException r0 = new java.lang.IllegalArgumentException
            r1 = r0
            java.lang.String r2 = "w needs to be 4 or 16"
            r1.<init>(r2)
            throw r0
        L23:
            r0 = r7
            int r0 = org.bouncycastle.pqc.crypto.xmss.XMSSUtil.log2(r0)
            r9 = r0
            r0 = r8
            r1 = 8
            r2 = r6
            int r2 = r2.length
            int r1 = r1 * r2
            r2 = r9
            int r1 = r1 / r2
            if (r0 <= r1) goto L3f
            java.lang.IllegalArgumentException r0 = new java.lang.IllegalArgumentException
            r1 = r0
            java.lang.String r2 = "outLength too big"
            r1.<init>(r2)
            throw r0
        L3f:
            java.util.ArrayList r0 = new java.util.ArrayList
            r1 = r0
            r1.<init>()
            r10 = r0
            r0 = 0
            r11 = r0
        L4b:
            r0 = r11
            r1 = r6
            int r1 = r1.length
            if (r0 >= r1) goto L8e
            r0 = 8
            r1 = r9
            int r0 = r0 - r1
            r12 = r0
        L59:
            r0 = r12
            if (r0 < 0) goto L88
            r0 = r10
            r1 = r6
            r2 = r11
            r1 = r1[r2]
            r2 = r12
            int r1 = r1 >> r2
            r2 = r7
            r3 = 1
            int r2 = r2 - r3
            r1 = r1 & r2
            java.lang.Integer r1 = java.lang.Integer.valueOf(r1)
            boolean r0 = r0.add(r1)
            r0 = r10
            int r0 = r0.size()
            r1 = r8
            if (r0 != r1) goto L7e
            r0 = r10
            return r0
        L7e:
            r0 = r12
            r1 = r9
            int r0 = r0 - r1
            r12 = r0
            goto L59
        L88:
            int r11 = r11 + 1
            goto L4b
        L8e:
            r0 = r10
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.pqc.crypto.xmss.WOTSPlus.convertToBaseW(byte[], int, int):java.util.List");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public byte[] getWOTSPlusSecretKey(byte[] bArr, OTSHashAddress oTSHashAddress) {
        return this.khf.PRF(bArr, ((OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(oTSHashAddress.getLayerAddress()).withTreeAddress(oTSHashAddress.getTreeAddress()).withOTSAddress(oTSHashAddress.getOTSAddress()).build()).toByteArray());
    }

    private byte[] expandSecretKeySeed(int i) {
        if (i < 0 || i >= this.params.getLen()) {
            throw new IllegalArgumentException("index out of bounds");
        }
        return this.khf.PRF(this.secretKeySeed, XMSSUtil.toBytesBigEndian(i, 32));
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public WOTSPlusParameters getParams() {
        return this.params;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public KeyedHashFunctions getKhf() {
        return this.khf;
    }

    protected byte[] getSecretKeySeed() {
        return Arrays.clone(this.secretKeySeed);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public byte[] getPublicSeed() {
        return Arrays.clone(this.publicSeed);
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [byte[], byte[][]] */
    protected WOTSPlusPrivateKeyParameters getPrivateKey() {
        ?? r0 = new byte[this.params.getLen()];
        for (int i = 0; i < r0.length; i++) {
            r0[i] = expandSecretKeySeed(i);
        }
        return new WOTSPlusPrivateKeyParameters(this.params, r0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Type inference failed for: r0v4, types: [byte[], byte[][]] */
    public WOTSPlusPublicKeyParameters getPublicKey(OTSHashAddress oTSHashAddress) {
        if (oTSHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        }
        ?? r0 = new byte[this.params.getLen()];
        for (int i = 0; i < this.params.getLen(); i++) {
            oTSHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(oTSHashAddress.getLayerAddress()).withTreeAddress(oTSHashAddress.getTreeAddress()).withOTSAddress(oTSHashAddress.getOTSAddress()).withChainAddress(i).withHashAddress(oTSHashAddress.getHashAddress()).withKeyAndMask(oTSHashAddress.getKeyAndMask()).build();
            r0[i] = chain(expandSecretKeySeed(i), 0, this.params.getWinternitzParameter() - 1, oTSHashAddress);
        }
        return new WOTSPlusPublicKeyParameters(this.params, r0);
    }
}