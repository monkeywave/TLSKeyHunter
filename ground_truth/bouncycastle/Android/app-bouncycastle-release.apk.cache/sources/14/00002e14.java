package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import org.bouncycastle.asn1.p009x9.ECNamedCurveTable;
import org.bouncycastle.asn1.p009x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.p010ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.p016ec.ECPoint;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.util.BigIntegers;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsECDomain */
/* loaded from: classes2.dex */
public class BcTlsECDomain implements TlsECDomain {
    protected final TlsECConfig config;
    protected final BcTlsCrypto crypto;
    protected final ECDomainParameters domainParameters;

    public BcTlsECDomain(BcTlsCrypto bcTlsCrypto, TlsECConfig tlsECConfig) {
        this.crypto = bcTlsCrypto;
        this.config = tlsECConfig;
        this.domainParameters = getDomainParameters(tlsECConfig);
    }

    public static BcTlsSecret calculateECDHAgreement(BcTlsCrypto bcTlsCrypto, ECPrivateKeyParameters eCPrivateKeyParameters, ECPublicKeyParameters eCPublicKeyParameters) {
        ECDHBasicAgreement eCDHBasicAgreement = new ECDHBasicAgreement();
        eCDHBasicAgreement.init(eCPrivateKeyParameters);
        return bcTlsCrypto.adoptLocalSecret(BigIntegers.asUnsignedByteArray(eCDHBasicAgreement.getFieldSize(), eCDHBasicAgreement.calculateAgreement(eCPublicKeyParameters)));
    }

    public static ECDomainParameters getDomainParameters(int i) {
        if (NamedGroup.refersToASpecificCurve(i)) {
            String curveName = NamedGroup.getCurveName(i);
            X9ECParameters byName = CustomNamedCurves.getByName(curveName);
            if (byName == null && (byName = ECNamedCurveTable.getByName(curveName)) == null) {
                return null;
            }
            return new ECDomainParameters(byName.getCurve(), byName.getG(), byName.getN(), byName.getH(), byName.getSeed());
        }
        return null;
    }

    public static ECDomainParameters getDomainParameters(TlsECConfig tlsECConfig) {
        return getDomainParameters(tlsECConfig.getNamedGroup());
    }

    public BcTlsSecret calculateECDHAgreement(ECPrivateKeyParameters eCPrivateKeyParameters, ECPublicKeyParameters eCPublicKeyParameters) {
        return calculateECDHAgreement(this.crypto, eCPrivateKeyParameters, eCPublicKeyParameters);
    }

    @Override // org.bouncycastle.tls.crypto.TlsECDomain
    public TlsAgreement createECDH() {
        return new BcTlsECDH(this);
    }

    public ECPoint decodePoint(byte[] bArr) {
        return this.domainParameters.getCurve().decodePoint(bArr);
    }

    public ECPublicKeyParameters decodePublicKey(byte[] bArr) throws IOException {
        try {
            return new ECPublicKeyParameters(decodePoint(bArr), this.domainParameters);
        } catch (RuntimeException e) {
            throw new TlsFatalAlert((short) 47, (Throwable) e);
        }
    }

    public byte[] encodePoint(ECPoint eCPoint) {
        return eCPoint.getEncoded(false);
    }

    public byte[] encodePublicKey(ECPublicKeyParameters eCPublicKeyParameters) {
        return encodePoint(eCPublicKeyParameters.getQ());
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        ECKeyPairGenerator eCKeyPairGenerator = new ECKeyPairGenerator();
        eCKeyPairGenerator.init(new ECKeyGenerationParameters(this.domainParameters, this.crypto.getSecureRandom()));
        return eCKeyPairGenerator.generateKeyPair();
    }
}