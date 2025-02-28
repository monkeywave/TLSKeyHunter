package org.bouncycastle.tls.crypto.impl.p018bc;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsKemConfig;
import org.bouncycastle.tls.crypto.TlsKemDomain;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsMLKemDomain */
/* loaded from: classes2.dex */
public class BcTlsMLKemDomain implements TlsKemDomain {
    protected final BcTlsCrypto crypto;
    protected final boolean isServer;
    protected final MLKEMParameters kyberParameters;

    public BcTlsMLKemDomain(BcTlsCrypto bcTlsCrypto, TlsKemConfig tlsKemConfig) {
        this.crypto = bcTlsCrypto;
        this.kyberParameters = getKyberParameters(tlsKemConfig.getNamedGroup());
        this.isServer = tlsKemConfig.isServer();
    }

    protected static MLKEMParameters getKyberParameters(int i) {
        if (i != 1896) {
            if (i != 4132) {
                switch (i) {
                    case NamedGroup.OQS_mlkem512 /* 583 */:
                        return MLKEMParameters.ml_kem_512;
                    case NamedGroup.OQS_mlkem768 /* 584 */:
                        break;
                    case NamedGroup.OQS_mlkem1024 /* 585 */:
                        break;
                    default:
                        return null;
                }
            }
            return MLKEMParameters.ml_kem_1024;
        }
        return MLKEMParameters.ml_kem_768;
    }

    public BcTlsSecret adoptLocalSecret(byte[] bArr) {
        return this.crypto.adoptLocalSecret(bArr);
    }

    @Override // org.bouncycastle.tls.crypto.TlsKemDomain
    public TlsAgreement createKem() {
        return new BcTlsMLKem(this);
    }

    public BcTlsSecret decapsulate(MLKEMPrivateKeyParameters mLKEMPrivateKeyParameters, byte[] bArr) {
        return adoptLocalSecret(new MLKEMExtractor(mLKEMPrivateKeyParameters).extractSecret(bArr));
    }

    public MLKEMPublicKeyParameters decodePublicKey(byte[] bArr) {
        return new MLKEMPublicKeyParameters(this.kyberParameters, bArr);
    }

    public SecretWithEncapsulation encapsulate(MLKEMPublicKeyParameters mLKEMPublicKeyParameters) {
        return new MLKEMGenerator(this.crypto.getSecureRandom()).generateEncapsulated(mLKEMPublicKeyParameters);
    }

    public byte[] encodePublicKey(MLKEMPublicKeyParameters mLKEMPublicKeyParameters) {
        return mLKEMPublicKeyParameters.getEncoded();
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        MLKEMKeyPairGenerator mLKEMKeyPairGenerator = new MLKEMKeyPairGenerator();
        mLKEMKeyPairGenerator.init(new MLKEMKeyGenerationParameters(this.crypto.getSecureRandom(), this.kyberParameters));
        return mLKEMKeyPairGenerator.generateKeyPair();
    }

    public boolean isServer() {
        return this.isServer;
    }
}