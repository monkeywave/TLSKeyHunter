package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.pqc.crypto.StateAwareMessageSigner;
import org.bouncycastle.pqc.crypto.xmss.OTSHashAddress;
import org.bouncycastle.pqc.crypto.xmss.XMSSSignature;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class XMSSSigner implements StateAwareMessageSigner {
    private boolean hasGenerated;
    private boolean initSign;
    private KeyedHashFunctions khf;
    private XMSSParameters params;
    private XMSSPrivateKeyParameters privateKey;
    private XMSSPublicKeyParameters publicKey;
    private WOTSPlus wotsPlus;

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
                XMSSPrivateKeyParameters xMSSPrivateKeyParameters = this.privateKey;
                if (xMSSPrivateKeyParameters != null) {
                    synchronized (xMSSPrivateKeyParameters) {
                        if (this.privateKey.getUsagesRemaining() <= 0) {
                            throw new ExhaustedPrivateKeyException("no usages of private key remaining");
                        }
                        if (this.privateKey.getBDSState().getAuthenticationPath().isEmpty()) {
                            throw new IllegalStateException("not initialized");
                        }
                        int index = this.privateKey.getIndex();
                        this.hasGenerated = true;
                        long j = index;
                        byte[] PRF = this.khf.PRF(this.privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(j, 32));
                        byteArray = new XMSSSignature.Builder(this.params).withIndex(index).withRandom(PRF).withWOTSPlusSignature(wotsSign(this.khf.HMsg(Arrays.concatenate(PRF, this.privateKey.getRoot(), XMSSUtil.toBytesBigEndian(j, this.params.getTreeDigestSize())), bArr), (OTSHashAddress) new OTSHashAddress.Builder().withOTSAddress(index).build())).withAuthPath(this.privateKey.getBDSState().getAuthenticationPath()).build().toByteArray();
                        this.privateKey.getBDSState().markUsed();
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
        synchronized (this.privateKey) {
            if (this.hasGenerated) {
                XMSSPrivateKeyParameters xMSSPrivateKeyParameters = this.privateKey;
                this.privateKey = null;
                return xMSSPrivateKeyParameters;
            }
            XMSSPrivateKeyParameters xMSSPrivateKeyParameters2 = this.privateKey;
            if (xMSSPrivateKeyParameters2 != null) {
                this.privateKey = xMSSPrivateKeyParameters2.getNextKey();
            }
            return xMSSPrivateKeyParameters2;
        }
    }

    public long getUsagesRemaining() {
        return this.privateKey.getUsagesRemaining();
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public void init(boolean z, CipherParameters cipherParameters) {
        XMSSParameters parameters;
        if (z) {
            this.initSign = true;
            this.hasGenerated = false;
            XMSSPrivateKeyParameters xMSSPrivateKeyParameters = (XMSSPrivateKeyParameters) cipherParameters;
            this.privateKey = xMSSPrivateKeyParameters;
            parameters = xMSSPrivateKeyParameters.getParameters();
        } else {
            this.initSign = false;
            XMSSPublicKeyParameters xMSSPublicKeyParameters = (XMSSPublicKeyParameters) cipherParameters;
            this.publicKey = xMSSPublicKeyParameters;
            parameters = xMSSPublicKeyParameters.getParameters();
        }
        this.params = parameters;
        WOTSPlus wOTSPlus = this.params.getWOTSPlus();
        this.wotsPlus = wOTSPlus;
        this.khf = wOTSPlus.getKhf();
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] bArr, byte[] bArr2) {
        XMSSSignature build = new XMSSSignature.Builder(this.params).withSignature(bArr2).build();
        int index = build.getIndex();
        this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], this.publicKey.getPublicSeed());
        long j = index;
        byte[] HMsg = this.khf.HMsg(Arrays.concatenate(build.getRandom(), this.publicKey.getRoot(), XMSSUtil.toBytesBigEndian(j, this.params.getTreeDigestSize())), bArr);
        int height = this.params.getHeight();
        return Arrays.constantTimeAreEqual(XMSSVerifierUtil.getRootNodeFromSignature(this.wotsPlus, height, HMsg, build, (OTSHashAddress) new OTSHashAddress.Builder().withOTSAddress(index).build(), XMSSUtil.getLeafIndex(j, height)).getValue(), this.publicKey.getRoot());
    }
}