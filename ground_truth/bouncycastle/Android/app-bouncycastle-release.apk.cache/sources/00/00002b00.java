package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;
import java.text.ParseException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class XMSS {
    private final XMSSParameters params;
    private XMSSPrivateKeyParameters privateKey;
    private SecureRandom prng;
    private XMSSPublicKeyParameters publicKey;
    private WOTSPlus wotsPlus;

    public XMSS(XMSSParameters xMSSParameters, SecureRandom secureRandom) {
        if (xMSSParameters == null) {
            throw new NullPointerException("params == null");
        }
        this.params = xMSSParameters;
        this.wotsPlus = xMSSParameters.getWOTSPlus();
        this.prng = secureRandom;
    }

    public XMSSPrivateKeyParameters exportPrivateKey() {
        return this.privateKey;
    }

    public XMSSPublicKeyParameters exportPublicKey() {
        return this.publicKey;
    }

    public void generateKeys() {
        XMSSKeyPairGenerator xMSSKeyPairGenerator = new XMSSKeyPairGenerator();
        xMSSKeyPairGenerator.init(new XMSSKeyGenerationParameters(getParams(), this.prng));
        AsymmetricCipherKeyPair generateKeyPair = xMSSKeyPairGenerator.generateKeyPair();
        this.privateKey = (XMSSPrivateKeyParameters) generateKeyPair.getPrivate();
        this.publicKey = (XMSSPublicKeyParameters) generateKeyPair.getPublic();
        this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], this.privateKey.getPublicSeed());
    }

    public int getIndex() {
        return this.privateKey.getIndex();
    }

    public XMSSParameters getParams() {
        return this.params;
    }

    public XMSSPrivateKeyParameters getPrivateKey() {
        return this.privateKey;
    }

    public byte[] getPublicSeed() {
        return this.privateKey.getPublicSeed();
    }

    public byte[] getRoot() {
        return this.privateKey.getRoot();
    }

    protected WOTSPlus getWOTSPlus() {
        return this.wotsPlus;
    }

    public void importState(XMSSPrivateKeyParameters xMSSPrivateKeyParameters, XMSSPublicKeyParameters xMSSPublicKeyParameters) {
        if (!Arrays.areEqual(xMSSPrivateKeyParameters.getRoot(), xMSSPublicKeyParameters.getRoot())) {
            throw new IllegalStateException("root of private key and public key do not match");
        }
        if (!Arrays.areEqual(xMSSPrivateKeyParameters.getPublicSeed(), xMSSPublicKeyParameters.getPublicSeed())) {
            throw new IllegalStateException("public seed of private key and public key do not match");
        }
        this.privateKey = xMSSPrivateKeyParameters;
        this.publicKey = xMSSPublicKeyParameters;
        this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], this.privateKey.getPublicSeed());
    }

    public void importState(byte[] bArr, byte[] bArr2) {
        if (bArr == null) {
            throw new NullPointerException("privateKey == null");
        }
        if (bArr2 == null) {
            throw new NullPointerException("publicKey == null");
        }
        XMSSPrivateKeyParameters build = new XMSSPrivateKeyParameters.Builder(this.params).withPrivateKey(bArr).build();
        XMSSPublicKeyParameters build2 = new XMSSPublicKeyParameters.Builder(this.params).withPublicKey(bArr2).build();
        if (!Arrays.areEqual(build.getRoot(), build2.getRoot())) {
            throw new IllegalStateException("root of private key and public key do not match");
        }
        if (!Arrays.areEqual(build.getPublicSeed(), build2.getPublicSeed())) {
            throw new IllegalStateException("public seed of private key and public key do not match");
        }
        this.privateKey = build;
        this.publicKey = build2;
        this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], this.privateKey.getPublicSeed());
    }

    protected void setIndex(int i) {
        this.privateKey = new XMSSPrivateKeyParameters.Builder(this.params).withSecretKeySeed(this.privateKey.getSecretKeySeed()).withSecretKeyPRF(this.privateKey.getSecretKeyPRF()).withPublicSeed(this.privateKey.getPublicSeed()).withRoot(this.privateKey.getRoot()).withBDSState(this.privateKey.getBDSState()).build();
    }

    protected void setPublicSeed(byte[] bArr) {
        this.privateKey = new XMSSPrivateKeyParameters.Builder(this.params).withSecretKeySeed(this.privateKey.getSecretKeySeed()).withSecretKeyPRF(this.privateKey.getSecretKeyPRF()).withPublicSeed(bArr).withRoot(getRoot()).withBDSState(this.privateKey.getBDSState()).build();
        this.publicKey = new XMSSPublicKeyParameters.Builder(this.params).withRoot(getRoot()).withPublicSeed(bArr).build();
        this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], bArr);
    }

    protected void setRoot(byte[] bArr) {
        this.privateKey = new XMSSPrivateKeyParameters.Builder(this.params).withSecretKeySeed(this.privateKey.getSecretKeySeed()).withSecretKeyPRF(this.privateKey.getSecretKeyPRF()).withPublicSeed(getPublicSeed()).withRoot(bArr).withBDSState(this.privateKey.getBDSState()).build();
        this.publicKey = new XMSSPublicKeyParameters.Builder(this.params).withRoot(bArr).withPublicSeed(getPublicSeed()).build();
    }

    public byte[] sign(byte[] bArr) {
        if (bArr != null) {
            XMSSSigner xMSSSigner = new XMSSSigner();
            xMSSSigner.init(true, this.privateKey);
            byte[] generateSignature = xMSSSigner.generateSignature(bArr);
            XMSSPrivateKeyParameters xMSSPrivateKeyParameters = (XMSSPrivateKeyParameters) xMSSSigner.getUpdatedPrivateKey();
            this.privateKey = xMSSPrivateKeyParameters;
            importState(xMSSPrivateKeyParameters, this.publicKey);
            return generateSignature;
        }
        throw new NullPointerException("message == null");
    }

    public boolean verifySignature(byte[] bArr, byte[] bArr2, byte[] bArr3) throws ParseException {
        if (bArr != null) {
            if (bArr2 != null) {
                if (bArr3 != null) {
                    XMSSSigner xMSSSigner = new XMSSSigner();
                    xMSSSigner.init(false, new XMSSPublicKeyParameters.Builder(getParams()).withPublicKey(bArr3).build());
                    return xMSSSigner.verifySignature(bArr, bArr2);
                }
                throw new NullPointerException("publicKey == null");
            }
            throw new NullPointerException("signature == null");
        }
        throw new NullPointerException("message == null");
    }

    protected WOTSPlusSignature wotsSign(byte[] bArr, OTSHashAddress oTSHashAddress) {
        if (bArr.length == this.params.getTreeDigestSize()) {
            if (oTSHashAddress != null) {
                WOTSPlus wOTSPlus = this.wotsPlus;
                wOTSPlus.importKeys(wOTSPlus.getWOTSPlusSecretKey(this.privateKey.getSecretKeySeed(), oTSHashAddress), getPublicSeed());
                return this.wotsPlus.sign(bArr, oTSHashAddress);
            }
            throw new NullPointerException("otsHashAddress == null");
        }
        throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
    }
}