package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;
import java.text.ParseException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/xmss/XMSS.class */
public class XMSS {
    private final XMSSParameters params;
    private WOTSPlus wotsPlus;
    private SecureRandom prng;
    private XMSSPrivateKeyParameters privateKey;
    private XMSSPublicKeyParameters publicKey;

    public XMSS(XMSSParameters xMSSParameters, SecureRandom secureRandom) {
        if (xMSSParameters == null) {
            throw new NullPointerException("params == null");
        }
        this.params = xMSSParameters;
        this.wotsPlus = xMSSParameters.getWOTSPlus();
        this.prng = secureRandom;
    }

    public void generateKeys() {
        XMSSKeyPairGenerator xMSSKeyPairGenerator = new XMSSKeyPairGenerator();
        xMSSKeyPairGenerator.init(new XMSSKeyGenerationParameters(getParams(), this.prng));
        AsymmetricCipherKeyPair generateKeyPair = xMSSKeyPairGenerator.generateKeyPair();
        this.privateKey = (XMSSPrivateKeyParameters) generateKeyPair.getPrivate();
        this.publicKey = (XMSSPublicKeyParameters) generateKeyPair.getPublic();
        this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], this.privateKey.getPublicSeed());
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

    public byte[] sign(byte[] bArr) {
        if (bArr == null) {
            throw new NullPointerException("message == null");
        }
        XMSSSigner xMSSSigner = new XMSSSigner();
        xMSSSigner.init(true, this.privateKey);
        byte[] generateSignature = xMSSSigner.generateSignature(bArr);
        this.privateKey = (XMSSPrivateKeyParameters) xMSSSigner.getUpdatedPrivateKey();
        importState(this.privateKey, this.publicKey);
        return generateSignature;
    }

    public boolean verifySignature(byte[] bArr, byte[] bArr2, byte[] bArr3) throws ParseException {
        if (bArr == null) {
            throw new NullPointerException("message == null");
        }
        if (bArr2 == null) {
            throw new NullPointerException("signature == null");
        }
        if (bArr3 == null) {
            throw new NullPointerException("publicKey == null");
        }
        XMSSSigner xMSSSigner = new XMSSSigner();
        xMSSSigner.init(false, new XMSSPublicKeyParameters.Builder(getParams()).withPublicKey(bArr3).build());
        return xMSSSigner.verifySignature(bArr, bArr2);
    }

    public XMSSPrivateKeyParameters exportPrivateKey() {
        return this.privateKey;
    }

    public XMSSPublicKeyParameters exportPublicKey() {
        return this.publicKey;
    }

    protected WOTSPlusSignature wotsSign(byte[] bArr, OTSHashAddress oTSHashAddress) {
        if (bArr.length != this.params.getTreeDigestSize()) {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }
        if (oTSHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        }
        this.wotsPlus.importKeys(this.wotsPlus.getWOTSPlusSecretKey(this.privateKey.getSecretKeySeed(), oTSHashAddress), getPublicSeed());
        return this.wotsPlus.sign(bArr, oTSHashAddress);
    }

    public XMSSParameters getParams() {
        return this.params;
    }

    protected WOTSPlus getWOTSPlus() {
        return this.wotsPlus;
    }

    public byte[] getRoot() {
        return this.privateKey.getRoot();
    }

    protected void setRoot(byte[] bArr) {
        this.privateKey = new XMSSPrivateKeyParameters.Builder(this.params).withSecretKeySeed(this.privateKey.getSecretKeySeed()).withSecretKeyPRF(this.privateKey.getSecretKeyPRF()).withPublicSeed(getPublicSeed()).withRoot(bArr).withBDSState(this.privateKey.getBDSState()).build();
        this.publicKey = new XMSSPublicKeyParameters.Builder(this.params).withRoot(bArr).withPublicSeed(getPublicSeed()).build();
    }

    public int getIndex() {
        return this.privateKey.getIndex();
    }

    protected void setIndex(int i) {
        this.privateKey = new XMSSPrivateKeyParameters.Builder(this.params).withSecretKeySeed(this.privateKey.getSecretKeySeed()).withSecretKeyPRF(this.privateKey.getSecretKeyPRF()).withPublicSeed(this.privateKey.getPublicSeed()).withRoot(this.privateKey.getRoot()).withBDSState(this.privateKey.getBDSState()).build();
    }

    public byte[] getPublicSeed() {
        return this.privateKey.getPublicSeed();
    }

    protected void setPublicSeed(byte[] bArr) {
        this.privateKey = new XMSSPrivateKeyParameters.Builder(this.params).withSecretKeySeed(this.privateKey.getSecretKeySeed()).withSecretKeyPRF(this.privateKey.getSecretKeyPRF()).withPublicSeed(bArr).withRoot(getRoot()).withBDSState(this.privateKey.getBDSState()).build();
        this.publicKey = new XMSSPublicKeyParameters.Builder(this.params).withRoot(getRoot()).withPublicSeed(bArr).build();
        this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], bArr);
    }

    public XMSSPrivateKeyParameters getPrivateKey() {
        return this.privateKey;
    }
}