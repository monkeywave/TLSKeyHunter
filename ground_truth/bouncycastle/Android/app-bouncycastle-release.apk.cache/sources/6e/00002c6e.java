package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSSigner;
import org.bouncycastle.pqc.jcajce.interfaces.StateAwareSignature;
import org.bouncycastle.pqc.jcajce.provider.xmss.DigestUtil;

/* loaded from: classes2.dex */
public class XMSSSignatureSpi extends Signature implements StateAwareSignature {
    private Digest digest;
    private SecureRandom random;
    private XMSSSigner signer;
    private ASN1ObjectIdentifier treeDigest;

    /* loaded from: classes2.dex */
    public static class generic extends XMSSSignatureSpi {
        public generic() {
            super("XMSS", new NullDigest(), new XMSSSigner());
        }
    }

    /* loaded from: classes2.dex */
    public static class withSha256 extends XMSSSignatureSpi {
        public withSha256() {
            super("XMSS-SHA256", new NullDigest(), new XMSSSigner());
        }
    }

    /* loaded from: classes2.dex */
    public static class withSha256andPrehash extends XMSSSignatureSpi {
        public withSha256andPrehash() {
            super("SHA256withXMSS-SHA256", new SHA256Digest(), new XMSSSigner());
        }
    }

    /* loaded from: classes2.dex */
    public static class withSha512 extends XMSSSignatureSpi {
        public withSha512() {
            super("XMSS-SHA512", new NullDigest(), new XMSSSigner());
        }
    }

    /* loaded from: classes2.dex */
    public static class withSha512andPrehash extends XMSSSignatureSpi {
        public withSha512andPrehash() {
            super("SHA512withXMSS-SHA512", new SHA512Digest(), new XMSSSigner());
        }
    }

    /* loaded from: classes2.dex */
    public static class withShake128 extends XMSSSignatureSpi {
        public withShake128() {
            super("XMSS-SHAKE128", new NullDigest(), new XMSSSigner());
        }
    }

    /* loaded from: classes2.dex */
    public static class withShake128_512andPrehash extends XMSSSignatureSpi {
        public withShake128_512andPrehash() {
            super("SHAKE128(512)withXMSS-SHAKE128", new DigestUtil.DoubleDigest(new SHAKEDigest(128)), new XMSSSigner());
        }
    }

    /* loaded from: classes2.dex */
    public static class withShake128andPrehash extends XMSSSignatureSpi {
        public withShake128andPrehash() {
            super("SHAKE128withXMSS-SHAKE128", new SHAKEDigest(128), new XMSSSigner());
        }
    }

    /* loaded from: classes2.dex */
    public static class withShake256 extends XMSSSignatureSpi {
        public withShake256() {
            super("XMSS-SHAKE256", new NullDigest(), new XMSSSigner());
        }
    }

    /* loaded from: classes2.dex */
    public static class withShake256_1024andPrehash extends XMSSSignatureSpi {
        public withShake256_1024andPrehash() {
            super("SHAKE256(1024)withXMSS-SHAKE256", new DigestUtil.DoubleDigest(new SHAKEDigest(256)), new XMSSSigner());
        }
    }

    /* loaded from: classes2.dex */
    public static class withShake256andPrehash extends XMSSSignatureSpi {
        public withShake256andPrehash() {
            super("SHAKE256withXMSS-SHAKE256", new SHAKEDigest(256), new XMSSSigner());
        }
    }

    protected XMSSSignatureSpi(String str) {
        super(str);
    }

    protected XMSSSignatureSpi(String str, Digest digest, XMSSSigner xMSSSigner) {
        super(str);
        this.digest = digest;
        this.signer = xMSSSigner;
    }

    @Override // java.security.SignatureSpi
    protected Object engineGetParameter(String str) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    @Override // java.security.SignatureSpi
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof BCXMSSPrivateKey)) {
            throw new InvalidKeyException("unknown private key passed to XMSS");
        }
        BCXMSSPrivateKey bCXMSSPrivateKey = (BCXMSSPrivateKey) privateKey;
        CipherParameters keyParams = bCXMSSPrivateKey.getKeyParams();
        this.treeDigest = bCXMSSPrivateKey.getTreeDigestOID();
        if (this.random != null) {
            keyParams = new ParametersWithRandom(keyParams, this.random);
        }
        this.digest.reset();
        this.signer.init(true, keyParams);
    }

    @Override // java.security.SignatureSpi
    protected void engineInitSign(PrivateKey privateKey, SecureRandom secureRandom) throws InvalidKeyException {
        this.random = secureRandom;
        engineInitSign(privateKey);
    }

    @Override // java.security.SignatureSpi
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof BCXMSSPublicKey)) {
            throw new InvalidKeyException("unknown public key passed to XMSS");
        }
        CipherParameters keyParams = ((BCXMSSPublicKey) publicKey).getKeyParams();
        this.treeDigest = null;
        this.digest.reset();
        this.signer.init(false, keyParams);
    }

    @Override // java.security.SignatureSpi
    protected void engineSetParameter(String str, Object obj) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    @Override // java.security.SignatureSpi
    protected void engineSetParameter(AlgorithmParameterSpec algorithmParameterSpec) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    @Override // java.security.SignatureSpi
    protected byte[] engineSign() throws SignatureException {
        try {
            return this.signer.generateSignature(DigestUtil.getDigestResult(this.digest));
        } catch (Exception e) {
            if (e instanceof IllegalStateException) {
                throw new SignatureException(e.getMessage(), e);
            }
            throw new SignatureException(e.toString(), e);
        }
    }

    @Override // java.security.SignatureSpi
    protected void engineUpdate(byte b) throws SignatureException {
        this.digest.update(b);
    }

    @Override // java.security.SignatureSpi
    protected void engineUpdate(byte[] bArr, int i, int i2) throws SignatureException {
        this.digest.update(bArr, i, i2);
    }

    @Override // java.security.SignatureSpi
    protected boolean engineVerify(byte[] bArr) throws SignatureException {
        return this.signer.verifySignature(DigestUtil.getDigestResult(this.digest), bArr);
    }

    @Override // org.bouncycastle.pqc.jcajce.interfaces.StateAwareSignature
    public PrivateKey getUpdatedPrivateKey() {
        if (this.treeDigest != null) {
            BCXMSSPrivateKey bCXMSSPrivateKey = new BCXMSSPrivateKey(this.treeDigest, (XMSSPrivateKeyParameters) this.signer.getUpdatedPrivateKey());
            this.treeDigest = null;
            return bCXMSSPrivateKey;
        }
        throw new IllegalStateException("signature object not in a signing state");
    }

    @Override // org.bouncycastle.pqc.jcajce.interfaces.StateAwareSignature
    public boolean isSigningCapable() {
        return (this.treeDigest == null || this.signer.getUsagesRemaining() == 0) ? false : true;
    }
}