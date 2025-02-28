package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.math.p016ec.ECPoint;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;

/* loaded from: classes2.dex */
public class JceTlsECDomain implements TlsECDomain {
    protected final JcaTlsCrypto crypto;
    protected final TlsECConfig ecConfig;
    protected final ECCurve ecCurve;
    protected final ECParameterSpec ecSpec;

    public JceTlsECDomain(JcaTlsCrypto jcaTlsCrypto, TlsECConfig tlsECConfig) {
        ECParameterSpec eCParameterSpec;
        int namedGroup = tlsECConfig.getNamedGroup();
        if (!NamedGroup.refersToAnECDSACurve(namedGroup) || (eCParameterSpec = ECUtil.getECParameterSpec(jcaTlsCrypto, NamedGroup.getCurveName(namedGroup))) == null) {
            throw new IllegalArgumentException("NamedGroup not supported: " + NamedGroup.getText(namedGroup));
        }
        this.crypto = jcaTlsCrypto;
        this.ecConfig = tlsECConfig;
        this.ecSpec = eCParameterSpec;
        this.ecCurve = ECUtil.convertCurve(eCParameterSpec.getCurve(), eCParameterSpec.getOrder(), eCParameterSpec.getCofactor());
    }

    public JceTlsSecret calculateECDHAgreement(PrivateKey privateKey, PublicKey publicKey) throws IOException {
        try {
            return this.crypto.adoptLocalSecret(this.crypto.calculateKeyAgreement("ECDH", privateKey, publicKey, "TlsPremasterSecret"));
        } catch (GeneralSecurityException e) {
            throw new TlsCryptoException("cannot calculate secret", e);
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsECDomain
    public TlsAgreement createECDH() {
        return new JceTlsECDH(this);
    }

    public ECPoint decodePoint(byte[] bArr) throws IOException {
        return this.ecCurve.decodePoint(bArr);
    }

    public PublicKey decodePublicKey(byte[] bArr) throws IOException {
        try {
            ECPoint normalize = decodePoint(bArr).normalize();
            return this.crypto.getHelper().createKeyFactory("EC").generatePublic(new ECPublicKeySpec(new java.security.spec.ECPoint(normalize.getAffineXCoord().toBigInteger(), normalize.getAffineYCoord().toBigInteger()), this.ecSpec));
        } catch (Exception e) {
            throw new TlsFatalAlert((short) 47, (Throwable) e);
        }
    }

    public byte[] encodePoint(ECPoint eCPoint) throws IOException {
        return eCPoint.getEncoded(false);
    }

    public byte[] encodePublicKey(PublicKey publicKey) throws IOException {
        if (publicKey instanceof ECPublicKey) {
            return encodePoint(((ECPublicKey) publicKey).getQ());
        }
        if (publicKey instanceof java.security.interfaces.ECPublicKey) {
            java.security.spec.ECPoint w = ((java.security.interfaces.ECPublicKey) publicKey).getW();
            return encodePoint(this.ecCurve.createPoint(w.getAffineX(), w.getAffineY()));
        }
        return SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getPublicKeyData().getOctets();
    }

    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator createKeyPairGenerator = this.crypto.getHelper().createKeyPairGenerator("EC");
            createKeyPairGenerator.initialize(this.ecSpec, this.crypto.getSecureRandom());
            return createKeyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw Exceptions.illegalStateException("unable to create key pair: " + e.getMessage(), e);
        }
    }
}