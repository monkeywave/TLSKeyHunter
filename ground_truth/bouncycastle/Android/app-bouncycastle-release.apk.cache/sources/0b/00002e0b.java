package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.DHGroup;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsDHDomain;
import org.bouncycastle.util.BigIntegers;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsDHDomain */
/* loaded from: classes2.dex */
public class BcTlsDHDomain implements TlsDHDomain {
    protected TlsDHConfig config;
    protected BcTlsCrypto crypto;
    protected DHParameters domainParameters;

    public BcTlsDHDomain(BcTlsCrypto bcTlsCrypto, TlsDHConfig tlsDHConfig) {
        this.crypto = bcTlsCrypto;
        this.config = tlsDHConfig;
        this.domainParameters = getDomainParameters(tlsDHConfig);
    }

    public static BcTlsSecret calculateDHAgreement(BcTlsCrypto bcTlsCrypto, DHPrivateKeyParameters dHPrivateKeyParameters, DHPublicKeyParameters dHPublicKeyParameters, boolean z) {
        DHBasicAgreement dHBasicAgreement = new DHBasicAgreement();
        dHBasicAgreement.init(dHPrivateKeyParameters);
        return bcTlsCrypto.adoptLocalSecret(encodeValue(dHPrivateKeyParameters.getParameters(), z, dHBasicAgreement.calculateAgreement(dHPublicKeyParameters)));
    }

    private static byte[] encodeValue(DHParameters dHParameters, boolean z, BigInteger bigInteger) {
        return z ? BigIntegers.asUnsignedByteArray(getValueLength(dHParameters), bigInteger) : BigIntegers.asUnsignedByteArray(bigInteger);
    }

    public static DHParameters getDomainParameters(TlsDHConfig tlsDHConfig) {
        DHGroup dHGroup = TlsDHUtils.getDHGroup(tlsDHConfig);
        if (dHGroup != null) {
            return new DHParameters(dHGroup.getP(), dHGroup.getG(), dHGroup.getQ(), dHGroup.getL());
        }
        throw new IllegalArgumentException("No DH configuration provided");
    }

    private static int getValueLength(DHParameters dHParameters) {
        return (dHParameters.getP().bitLength() + 7) / 8;
    }

    public BcTlsSecret calculateDHAgreement(DHPrivateKeyParameters dHPrivateKeyParameters, DHPublicKeyParameters dHPublicKeyParameters) {
        return calculateDHAgreement(this.crypto, dHPrivateKeyParameters, dHPublicKeyParameters, this.config.isPadded());
    }

    @Override // org.bouncycastle.tls.crypto.TlsDHDomain
    public TlsAgreement createDH() {
        return new BcTlsDH(this);
    }

    public BigInteger decodeParameter(byte[] bArr) throws IOException {
        if (!this.config.isPadded() || getValueLength(this.domainParameters) == bArr.length) {
            return new BigInteger(1, bArr);
        }
        throw new TlsFatalAlert((short) 47);
    }

    public DHPublicKeyParameters decodePublicKey(byte[] bArr) throws IOException {
        try {
            return new DHPublicKeyParameters(decodeParameter(bArr), this.domainParameters);
        } catch (RuntimeException e) {
            throw new TlsFatalAlert((short) 40, (Throwable) e);
        }
    }

    public byte[] encodeParameter(BigInteger bigInteger) {
        return encodeValue(this.domainParameters, this.config.isPadded(), bigInteger);
    }

    public byte[] encodePublicKey(DHPublicKeyParameters dHPublicKeyParameters) {
        return encodeValue(this.domainParameters, true, dHPublicKeyParameters.getY());
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        DHBasicKeyPairGenerator dHBasicKeyPairGenerator = new DHBasicKeyPairGenerator();
        dHBasicKeyPairGenerator.init(new DHKeyGenerationParameters(this.crypto.getSecureRandom(), this.domainParameters));
        return dHBasicKeyPairGenerator.generateKeyPair();
    }
}