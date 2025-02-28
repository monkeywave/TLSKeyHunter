package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.StateAwareMessageSigner;
import org.bouncycastle.pqc.crypto.xmss.OTSHashAddress;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTSignature;
import org.bouncycastle.pqc.crypto.xmss.XMSSReducedSignature;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class XMSSMTSigner implements StateAwareMessageSigner {
    private boolean hasGenerated;
    private boolean initSign;
    private XMSSMTParameters params;
    private XMSSMTPrivateKeyParameters privateKey;
    private XMSSMTPublicKeyParameters publicKey;
    private WOTSPlus wotsPlus;
    private XMSSParameters xmssParams;

    private WOTSPlusSignature wotsSign(byte[] bArr, OTSHashAddress oTSHashAddress) {
        if (bArr.length == this.params.getTreeDigestSize()) {
            if (oTSHashAddress != null) {
                WOTSPlus wOTSPlus = this.wotsPlus;
                wOTSPlus.importKeys(wOTSPlus.getWOTSPlusSecretKey(this.privateKey.getSecretKeySeed(), oTSHashAddress), this.privateKey.getPublicSeed());
                return this.wotsPlus.sign(bArr, oTSHashAddress);
            }
            throw new NullPointerException("otsHashAddress == null");
        }
        throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] bArr) {
        byte[] byteArray;
        if (bArr != null) {
            if (this.initSign) {
                XMSSMTPrivateKeyParameters xMSSMTPrivateKeyParameters = this.privateKey;
                if (xMSSMTPrivateKeyParameters != null) {
                    synchronized (xMSSMTPrivateKeyParameters) {
                        if (this.privateKey.getUsagesRemaining() <= 0) {
                            throw new IllegalStateException("no usages of private key remaining");
                        }
                        if (this.privateKey.getBDSState().isEmpty()) {
                            throw new IllegalStateException("not initialized");
                        }
                        BDSStateMap bDSState = this.privateKey.getBDSState();
                        long index = this.privateKey.getIndex();
                        this.params.getHeight();
                        int height = this.xmssParams.getHeight();
                        if (this.privateKey.getUsagesRemaining() <= 0) {
                            throw new IllegalStateException("index out of bounds");
                        }
                        byte[] PRF = this.wotsPlus.getKhf().PRF(this.privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(index, 32));
                        byte[] HMsg = this.wotsPlus.getKhf().HMsg(Arrays.concatenate(PRF, this.privateKey.getRoot(), XMSSUtil.toBytesBigEndian(index, this.params.getTreeDigestSize())), bArr);
                        this.hasGenerated = true;
                        XMSSMTSignature build = new XMSSMTSignature.Builder(this.params).withIndex(index).withRandom(PRF).build();
                        long treeIndex = XMSSUtil.getTreeIndex(index, height);
                        int leafIndex = XMSSUtil.getLeafIndex(index, height);
                        this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], this.privateKey.getPublicSeed());
                        OTSHashAddress oTSHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withTreeAddress(treeIndex).withOTSAddress(leafIndex).build();
                        if (bDSState.get(0) == null || leafIndex == 0) {
                            bDSState.put(0, new BDS(this.xmssParams, this.privateKey.getPublicSeed(), this.privateKey.getSecretKeySeed(), oTSHashAddress));
                        }
                        build.getReducedSignatures().add(new XMSSReducedSignature.Builder(this.xmssParams).withWOTSPlusSignature(wotsSign(HMsg, oTSHashAddress)).withAuthPath(bDSState.get(0).getAuthenticationPath()).build());
                        for (int i = 1; i < this.params.getLayers(); i++) {
                            XMSSNode root = bDSState.get(i - 1).getRoot();
                            int leafIndex2 = XMSSUtil.getLeafIndex(treeIndex, height);
                            treeIndex = XMSSUtil.getTreeIndex(treeIndex, height);
                            OTSHashAddress oTSHashAddress2 = (OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(i).withTreeAddress(treeIndex).withOTSAddress(leafIndex2).build();
                            WOTSPlusSignature wotsSign = wotsSign(root.getValue(), oTSHashAddress2);
                            if (bDSState.get(i) == null || XMSSUtil.isNewBDSInitNeeded(index, height, i)) {
                                bDSState.put(i, new BDS(this.xmssParams, this.privateKey.getPublicSeed(), this.privateKey.getSecretKeySeed(), oTSHashAddress2));
                            }
                            build.getReducedSignatures().add(new XMSSReducedSignature.Builder(this.xmssParams).withWOTSPlusSignature(wotsSign).withAuthPath(bDSState.get(i).getAuthenticationPath()).build());
                        }
                        byteArray = build.toByteArray();
                        this.privateKey.rollKey();
                    }
                    return byteArray;
                }
                throw new IllegalStateException("signing key no longer usable");
            }
            throw new IllegalStateException("signer not initialized for signature generation");
        }
        throw new NullPointerException("message == null");
    }

    @Override // org.bouncycastle.pqc.crypto.StateAwareMessageSigner
    public AsymmetricKeyParameter getUpdatedPrivateKey() {
        if (this.hasGenerated) {
            XMSSMTPrivateKeyParameters xMSSMTPrivateKeyParameters = this.privateKey;
            this.privateKey = null;
            return xMSSMTPrivateKeyParameters;
        }
        XMSSMTPrivateKeyParameters xMSSMTPrivateKeyParameters2 = this.privateKey;
        if (xMSSMTPrivateKeyParameters2 != null) {
            this.privateKey = xMSSMTPrivateKeyParameters2.getNextKey();
        }
        return xMSSMTPrivateKeyParameters2;
    }

    public long getUsagesRemaining() {
        return this.privateKey.getUsagesRemaining();
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public void init(boolean z, CipherParameters cipherParameters) {
        XMSSMTParameters parameters;
        if (z) {
            this.initSign = true;
            this.hasGenerated = false;
            XMSSMTPrivateKeyParameters xMSSMTPrivateKeyParameters = (XMSSMTPrivateKeyParameters) cipherParameters;
            this.privateKey = xMSSMTPrivateKeyParameters;
            parameters = xMSSMTPrivateKeyParameters.getParameters();
        } else {
            this.initSign = false;
            XMSSMTPublicKeyParameters xMSSMTPublicKeyParameters = (XMSSMTPublicKeyParameters) cipherParameters;
            this.publicKey = xMSSMTPublicKeyParameters;
            parameters = xMSSMTPublicKeyParameters.getParameters();
        }
        this.params = parameters;
        this.xmssParams = parameters.getXMSSParameters();
        this.wotsPlus = this.params.getWOTSPlus();
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] bArr, byte[] bArr2) {
        if (bArr != null) {
            if (bArr2 != null) {
                if (this.publicKey != null) {
                    XMSSMTSignature build = new XMSSMTSignature.Builder(this.params).withSignature(bArr2).build();
                    byte[] HMsg = this.wotsPlus.getKhf().HMsg(Arrays.concatenate(build.getRandom(), this.publicKey.getRoot(), XMSSUtil.toBytesBigEndian(build.getIndex(), this.params.getTreeDigestSize())), bArr);
                    long index = build.getIndex();
                    int height = this.xmssParams.getHeight();
                    long treeIndex = XMSSUtil.getTreeIndex(index, height);
                    int leafIndex = XMSSUtil.getLeafIndex(index, height);
                    this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], this.publicKey.getPublicSeed());
                    OTSHashAddress oTSHashAddress = (OTSHashAddress) new OTSHashAddress.Builder().withTreeAddress(treeIndex).withOTSAddress(leafIndex).build();
                    XMSSNode rootNodeFromSignature = XMSSVerifierUtil.getRootNodeFromSignature(this.wotsPlus, height, HMsg, build.getReducedSignatures().get(0), oTSHashAddress, leafIndex);
                    int i = 1;
                    while (i < this.params.getLayers()) {
                        int leafIndex2 = XMSSUtil.getLeafIndex(treeIndex, height);
                        long treeIndex2 = XMSSUtil.getTreeIndex(treeIndex, height);
                        OTSHashAddress oTSHashAddress2 = (OTSHashAddress) new OTSHashAddress.Builder().withLayerAddress(i).withTreeAddress(treeIndex2).withOTSAddress(leafIndex2).build();
                        rootNodeFromSignature = XMSSVerifierUtil.getRootNodeFromSignature(this.wotsPlus, height, rootNodeFromSignature.getValue(), build.getReducedSignatures().get(i), oTSHashAddress2, leafIndex2);
                        i++;
                        treeIndex = treeIndex2;
                    }
                    return Arrays.constantTimeAreEqual(rootNodeFromSignature.getValue(), this.publicKey.getRoot());
                }
                throw new NullPointerException("publicKey == null");
            }
            throw new NullPointerException("signature == null");
        }
        throw new NullPointerException("message == null");
    }
}