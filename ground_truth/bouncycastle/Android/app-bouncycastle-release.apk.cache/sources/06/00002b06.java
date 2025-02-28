package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;
import java.text.ParseException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public final class XMSSMT {
    private XMSSMTParameters params;
    private XMSSMTPrivateKeyParameters privateKey;
    private SecureRandom prng;
    private XMSSMTPublicKeyParameters publicKey;
    private XMSSParameters xmssParams;

    public XMSSMT(XMSSMTParameters xMSSMTParameters, SecureRandom secureRandom) {
        if (xMSSMTParameters == null) {
            throw new NullPointerException("params == null");
        }
        this.params = xMSSMTParameters;
        this.xmssParams = xMSSMTParameters.getXMSSParameters();
        this.prng = secureRandom;
        this.privateKey = new XMSSMTPrivateKeyParameters.Builder(xMSSMTParameters).build();
        this.publicKey = new XMSSMTPublicKeyParameters.Builder(xMSSMTParameters).build();
    }

    private void importState(XMSSMTPrivateKeyParameters xMSSMTPrivateKeyParameters, XMSSMTPublicKeyParameters xMSSMTPublicKeyParameters) {
        this.xmssParams.getWOTSPlus().importKeys(new byte[this.params.getTreeDigestSize()], this.privateKey.getPublicSeed());
        this.privateKey = xMSSMTPrivateKeyParameters;
        this.publicKey = xMSSMTPublicKeyParameters;
    }

    public byte[] exportPrivateKey() {
        return this.privateKey.toByteArray();
    }

    public byte[] exportPublicKey() {
        return this.publicKey.toByteArray();
    }

    public void generateKeys() {
        XMSSMTKeyPairGenerator xMSSMTKeyPairGenerator = new XMSSMTKeyPairGenerator();
        xMSSMTKeyPairGenerator.init(new XMSSMTKeyGenerationParameters(getParams(), this.prng));
        AsymmetricCipherKeyPair generateKeyPair = xMSSMTKeyPairGenerator.generateKeyPair();
        this.privateKey = (XMSSMTPrivateKeyParameters) generateKeyPair.getPrivate();
        XMSSMTPublicKeyParameters xMSSMTPublicKeyParameters = (XMSSMTPublicKeyParameters) generateKeyPair.getPublic();
        this.publicKey = xMSSMTPublicKeyParameters;
        importState(this.privateKey, xMSSMTPublicKeyParameters);
    }

    public XMSSMTParameters getParams() {
        return this.params;
    }

    public byte[] getPublicSeed() {
        return this.privateKey.getPublicSeed();
    }

    protected XMSSParameters getXMSS() {
        return this.xmssParams;
    }

    public void importState(byte[] bArr, byte[] bArr2) {
        if (bArr == null) {
            throw new NullPointerException("privateKey == null");
        }
        if (bArr2 == null) {
            throw new NullPointerException("publicKey == null");
        }
        XMSSMTPrivateKeyParameters build = new XMSSMTPrivateKeyParameters.Builder(this.params).withPrivateKey(bArr).build();
        XMSSMTPublicKeyParameters build2 = new XMSSMTPublicKeyParameters.Builder(this.params).withPublicKey(bArr2).build();
        if (!Arrays.areEqual(build.getRoot(), build2.getRoot())) {
            throw new IllegalStateException("root of private key and public key do not match");
        }
        if (!Arrays.areEqual(build.getPublicSeed(), build2.getPublicSeed())) {
            throw new IllegalStateException("public seed of private key and public key do not match");
        }
        this.xmssParams.getWOTSPlus().importKeys(new byte[this.params.getTreeDigestSize()], build.getPublicSeed());
        this.privateKey = build;
        this.publicKey = build2;
    }

    public byte[] sign(byte[] bArr) {
        if (bArr != null) {
            XMSSMTSigner xMSSMTSigner = new XMSSMTSigner();
            xMSSMTSigner.init(true, this.privateKey);
            byte[] generateSignature = xMSSMTSigner.generateSignature(bArr);
            XMSSMTPrivateKeyParameters xMSSMTPrivateKeyParameters = (XMSSMTPrivateKeyParameters) xMSSMTSigner.getUpdatedPrivateKey();
            this.privateKey = xMSSMTPrivateKeyParameters;
            importState(xMSSMTPrivateKeyParameters, this.publicKey);
            return generateSignature;
        }
        throw new NullPointerException("message == null");
    }

    public boolean verifySignature(byte[] bArr, byte[] bArr2, byte[] bArr3) throws ParseException {
        if (bArr != null) {
            if (bArr2 != null) {
                if (bArr3 != null) {
                    XMSSMTSigner xMSSMTSigner = new XMSSMTSigner();
                    xMSSMTSigner.init(false, new XMSSMTPublicKeyParameters.Builder(getParams()).withPublicKey(bArr3).build());
                    return xMSSMTSigner.verifySignature(bArr, bArr2);
                }
                throw new NullPointerException("publicKey == null");
            }
            throw new NullPointerException("signature == null");
        }
        throw new NullPointerException("message == null");
    }
}