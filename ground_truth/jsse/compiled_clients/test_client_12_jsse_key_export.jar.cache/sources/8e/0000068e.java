package org.bouncycastle.jcajce.provider.asymmetric.p007dh;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.agreement.DHUnifiedAgreement;
import org.bouncycastle.crypto.agreement.MQVBasicAgreement;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.agreement.kdf.DHKEKGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.DHMQVPrivateParameters;
import org.bouncycastle.crypto.params.DHMQVPublicParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DHUPrivateParameters;
import org.bouncycastle.crypto.params.DHUPublicParameters;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
import org.bouncycastle.jcajce.spec.DHUParameterSpec;
import org.bouncycastle.jcajce.spec.MQVParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;

/* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi.class */
public class KeyAgreementSpi extends BaseAgreementSpi {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private final DHUnifiedAgreement unifiedAgreement;
    private final BasicAgreement mqvAgreement;
    private DHUParameterSpec dheParameters;
    private MQVParameterSpec mqvParameters;

    /* renamed from: x */
    private BigInteger f594x;

    /* renamed from: p */
    private BigInteger f595p;

    /* renamed from: g */
    private BigInteger f596g;
    private byte[] result;

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHUwithSHA1CKDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHUwithSHA1CKDF.class */
    public static class DHUwithSHA1CKDF extends KeyAgreementSpi {
        public DHUwithSHA1CKDF() {
            super("DHUwithSHA1CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA1()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHUwithSHA1KDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHUwithSHA1KDF.class */
    public static class DHUwithSHA1KDF extends KeyAgreementSpi {
        public DHUwithSHA1KDF() {
            super("DHUwithSHA1KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHUwithSHA224CKDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHUwithSHA224CKDF.class */
    public static class DHUwithSHA224CKDF extends KeyAgreementSpi {
        public DHUwithSHA224CKDF() {
            super("DHUwithSHA224CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA224()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHUwithSHA224KDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHUwithSHA224KDF.class */
    public static class DHUwithSHA224KDF extends KeyAgreementSpi {
        public DHUwithSHA224KDF() {
            super("DHUwithSHA224KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA224()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHUwithSHA256CKDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHUwithSHA256CKDF.class */
    public static class DHUwithSHA256CKDF extends KeyAgreementSpi {
        public DHUwithSHA256CKDF() {
            super("DHUwithSHA256CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA256()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHUwithSHA256KDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHUwithSHA256KDF.class */
    public static class DHUwithSHA256KDF extends KeyAgreementSpi {
        public DHUwithSHA256KDF() {
            super("DHUwithSHA256KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA256()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHUwithSHA384CKDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHUwithSHA384CKDF.class */
    public static class DHUwithSHA384CKDF extends KeyAgreementSpi {
        public DHUwithSHA384CKDF() {
            super("DHUwithSHA384CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA384()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHUwithSHA384KDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHUwithSHA384KDF.class */
    public static class DHUwithSHA384KDF extends KeyAgreementSpi {
        public DHUwithSHA384KDF() {
            super("DHUwithSHA384KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA384()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHUwithSHA512CKDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHUwithSHA512CKDF.class */
    public static class DHUwithSHA512CKDF extends KeyAgreementSpi {
        public DHUwithSHA512CKDF() {
            super("DHUwithSHA512CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA512()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHUwithSHA512KDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHUwithSHA512KDF.class */
    public static class DHUwithSHA512KDF extends KeyAgreementSpi {
        public DHUwithSHA512KDF() {
            super("DHUwithSHA512KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA512()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHwithRFC2631KDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHwithRFC2631KDF.class */
    public static class DHwithRFC2631KDF extends KeyAgreementSpi {
        public DHwithRFC2631KDF() {
            super("DHwithRFC2631KDF", new DHKEKGenerator(DigestFactory.createSHA1()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHwithSHA1CKDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHwithSHA1CKDF.class */
    public static class DHwithSHA1CKDF extends KeyAgreementSpi {
        public DHwithSHA1CKDF() {
            super("DHwithSHA1CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA1()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHwithSHA1KDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHwithSHA1KDF.class */
    public static class DHwithSHA1KDF extends KeyAgreementSpi {
        public DHwithSHA1KDF() {
            super("DHwithSHA1CKDF", new KDF2BytesGenerator(DigestFactory.createSHA1()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHwithSHA224CKDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHwithSHA224CKDF.class */
    public static class DHwithSHA224CKDF extends KeyAgreementSpi {
        public DHwithSHA224CKDF() {
            super("DHwithSHA224CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA224()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHwithSHA224KDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHwithSHA224KDF.class */
    public static class DHwithSHA224KDF extends KeyAgreementSpi {
        public DHwithSHA224KDF() {
            super("DHwithSHA224CKDF", new KDF2BytesGenerator(DigestFactory.createSHA224()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHwithSHA256CKDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHwithSHA256CKDF.class */
    public static class DHwithSHA256CKDF extends KeyAgreementSpi {
        public DHwithSHA256CKDF() {
            super("DHwithSHA256CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA256()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHwithSHA256KDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHwithSHA256KDF.class */
    public static class DHwithSHA256KDF extends KeyAgreementSpi {
        public DHwithSHA256KDF() {
            super("DHwithSHA256CKDF", new KDF2BytesGenerator(DigestFactory.createSHA256()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHwithSHA384CKDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHwithSHA384CKDF.class */
    public static class DHwithSHA384CKDF extends KeyAgreementSpi {
        public DHwithSHA384CKDF() {
            super("DHwithSHA384CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA384()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHwithSHA384KDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHwithSHA384KDF.class */
    public static class DHwithSHA384KDF extends KeyAgreementSpi {
        public DHwithSHA384KDF() {
            super("DHwithSHA384KDF", new KDF2BytesGenerator(DigestFactory.createSHA384()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHwithSHA512CKDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHwithSHA512CKDF.class */
    public static class DHwithSHA512CKDF extends KeyAgreementSpi {
        public DHwithSHA512CKDF() {
            super("DHwithSHA512CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA512()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$DHwithSHA512KDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$DHwithSHA512KDF.class */
    public static class DHwithSHA512KDF extends KeyAgreementSpi {
        public DHwithSHA512KDF() {
            super("DHwithSHA512KDF", new KDF2BytesGenerator(DigestFactory.createSHA512()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$MQVwithSHA1CKDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$MQVwithSHA1CKDF.class */
    public static class MQVwithSHA1CKDF extends KeyAgreementSpi {
        public MQVwithSHA1CKDF() {
            super("MQVwithSHA1CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA1()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$MQVwithSHA1KDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$MQVwithSHA1KDF.class */
    public static class MQVwithSHA1KDF extends KeyAgreementSpi {
        public MQVwithSHA1KDF() {
            super("MQVwithSHA1KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$MQVwithSHA224CKDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$MQVwithSHA224CKDF.class */
    public static class MQVwithSHA224CKDF extends KeyAgreementSpi {
        public MQVwithSHA224CKDF() {
            super("MQVwithSHA224CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA224()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$MQVwithSHA224KDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$MQVwithSHA224KDF.class */
    public static class MQVwithSHA224KDF extends KeyAgreementSpi {
        public MQVwithSHA224KDF() {
            super("MQVwithSHA224KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA224()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$MQVwithSHA256CKDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$MQVwithSHA256CKDF.class */
    public static class MQVwithSHA256CKDF extends KeyAgreementSpi {
        public MQVwithSHA256CKDF() {
            super("MQVwithSHA256CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA256()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$MQVwithSHA256KDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$MQVwithSHA256KDF.class */
    public static class MQVwithSHA256KDF extends KeyAgreementSpi {
        public MQVwithSHA256KDF() {
            super("MQVwithSHA256KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA256()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$MQVwithSHA384CKDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$MQVwithSHA384CKDF.class */
    public static class MQVwithSHA384CKDF extends KeyAgreementSpi {
        public MQVwithSHA384CKDF() {
            super("MQVwithSHA384CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA384()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$MQVwithSHA384KDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$MQVwithSHA384KDF.class */
    public static class MQVwithSHA384KDF extends KeyAgreementSpi {
        public MQVwithSHA384KDF() {
            super("MQVwithSHA384KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA384()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$MQVwithSHA512CKDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$MQVwithSHA512CKDF.class */
    public static class MQVwithSHA512CKDF extends KeyAgreementSpi {
        public MQVwithSHA512CKDF() {
            super("MQVwithSHA512CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA512()));
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi$MQVwithSHA512KDF */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi$MQVwithSHA512KDF.class */
    public static class MQVwithSHA512KDF extends KeyAgreementSpi {
        public MQVwithSHA512KDF() {
            super("MQVwithSHA512KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA512()));
        }
    }

    public KeyAgreementSpi() {
        this("Diffie-Hellman", null);
    }

    public KeyAgreementSpi(String str, DerivationFunction derivationFunction) {
        super(str, derivationFunction);
        this.unifiedAgreement = null;
        this.mqvAgreement = null;
    }

    public KeyAgreementSpi(String str, DHUnifiedAgreement dHUnifiedAgreement, DerivationFunction derivationFunction) {
        super(str, derivationFunction);
        this.unifiedAgreement = dHUnifiedAgreement;
        this.mqvAgreement = null;
    }

    public KeyAgreementSpi(String str, BasicAgreement basicAgreement, DerivationFunction derivationFunction) {
        super(str, derivationFunction);
        this.unifiedAgreement = null;
        this.mqvAgreement = basicAgreement;
    }

    protected byte[] bigIntToBytes(BigInteger bigInteger) {
        int bitLength = (this.f595p.bitLength() + 7) / 8;
        byte[] byteArray = bigInteger.toByteArray();
        if (byteArray.length == bitLength) {
            return byteArray;
        }
        if (byteArray[0] == 0 && byteArray.length == bitLength + 1) {
            byte[] bArr = new byte[byteArray.length - 1];
            System.arraycopy(byteArray, 1, bArr, 0, bArr.length);
            return bArr;
        }
        byte[] bArr2 = new byte[bitLength];
        System.arraycopy(byteArray, 0, bArr2, bArr2.length - byteArray.length, byteArray.length);
        return bArr2;
    }

    @Override // javax.crypto.KeyAgreementSpi
    protected Key engineDoPhase(Key key, boolean z) throws InvalidKeyException, IllegalStateException {
        if (this.f594x == null) {
            throw new IllegalStateException("Diffie-Hellman not initialised.");
        }
        if (key instanceof DHPublicKey) {
            DHPublicKey dHPublicKey = (DHPublicKey) key;
            if (dHPublicKey.getParams().getG().equals(this.f596g) && dHPublicKey.getParams().getP().equals(this.f595p)) {
                BigInteger y = ((DHPublicKey) key).getY();
                if (y == null || y.compareTo(TWO) < 0 || y.compareTo(this.f595p.subtract(ONE)) >= 0) {
                    throw new InvalidKeyException("Invalid DH PublicKey");
                }
                if (this.unifiedAgreement != null) {
                    if (z) {
                        this.result = this.unifiedAgreement.calculateAgreement(new DHUPublicParameters(generatePublicKeyParameter((PublicKey) key), generatePublicKeyParameter(this.dheParameters.getOtherPartyEphemeralKey())));
                        return null;
                    }
                    throw new IllegalStateException("unified Diffie-Hellman can use only two key pairs");
                } else if (this.mqvAgreement != null) {
                    if (z) {
                        this.result = bigIntToBytes(this.mqvAgreement.calculateAgreement(new DHMQVPublicParameters(generatePublicKeyParameter((PublicKey) key), generatePublicKeyParameter(this.mqvParameters.getOtherPartyEphemeralKey()))));
                        return null;
                    }
                    throw new IllegalStateException("MQV Diffie-Hellman can use only two key pairs");
                } else {
                    BigInteger modPow = y.modPow(this.f594x, this.f595p);
                    if (modPow.compareTo(ONE) == 0) {
                        throw new InvalidKeyException("Shared key can't be 1");
                    }
                    this.result = bigIntToBytes(modPow);
                    if (z) {
                        return null;
                    }
                    return new BCDHPublicKey(modPow, dHPublicKey.getParams());
                }
            }
            throw new InvalidKeyException("DHPublicKey not for this KeyAgreement!");
        }
        throw new InvalidKeyException("DHKeyAgreement doPhase requires DHPublicKey");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi, javax.crypto.KeyAgreementSpi
    public byte[] engineGenerateSecret() throws IllegalStateException {
        if (this.f594x == null) {
            throw new IllegalStateException("Diffie-Hellman not initialised.");
        }
        return super.engineGenerateSecret();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi, javax.crypto.KeyAgreementSpi
    public int engineGenerateSecret(byte[] bArr, int i) throws IllegalStateException, ShortBufferException {
        if (this.f594x == null) {
            throw new IllegalStateException("Diffie-Hellman not initialised.");
        }
        return super.engineGenerateSecret(bArr, i);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi, javax.crypto.KeyAgreementSpi
    public SecretKey engineGenerateSecret(String str) throws NoSuchAlgorithmException {
        if (this.f594x == null) {
            throw new IllegalStateException("Diffie-Hellman not initialised.");
        }
        return str.equals("TlsPremasterSecret") ? new SecretKeySpec(trimZeroes(this.result), str) : super.engineGenerateSecret(str);
    }

    @Override // javax.crypto.KeyAgreementSpi
    protected void engineInit(Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(key instanceof DHPrivateKey)) {
            throw new InvalidKeyException("DHKeyAgreement requires DHPrivateKey for initialisation");
        }
        DHPrivateKey dHPrivateKey = (DHPrivateKey) key;
        if (algorithmParameterSpec == null) {
            this.f595p = dHPrivateKey.getParams().getP();
            this.f596g = dHPrivateKey.getParams().getG();
        } else if (algorithmParameterSpec instanceof DHParameterSpec) {
            DHParameterSpec dHParameterSpec = (DHParameterSpec) algorithmParameterSpec;
            this.f595p = dHParameterSpec.getP();
            this.f596g = dHParameterSpec.getG();
            this.dheParameters = null;
            this.ukmParameters = null;
        } else if (algorithmParameterSpec instanceof DHUParameterSpec) {
            if (this.unifiedAgreement == null) {
                throw new InvalidAlgorithmParameterException("agreement algorithm not DHU based");
            }
            this.f595p = dHPrivateKey.getParams().getP();
            this.f596g = dHPrivateKey.getParams().getG();
            this.dheParameters = (DHUParameterSpec) algorithmParameterSpec;
            this.ukmParameters = ((DHUParameterSpec) algorithmParameterSpec).getUserKeyingMaterial();
            if (this.dheParameters.getEphemeralPublicKey() != null) {
                this.unifiedAgreement.init(new DHUPrivateParameters(generatePrivateKeyParameter(dHPrivateKey), generatePrivateKeyParameter(this.dheParameters.getEphemeralPrivateKey()), generatePublicKeyParameter(this.dheParameters.getEphemeralPublicKey())));
            } else {
                this.unifiedAgreement.init(new DHUPrivateParameters(generatePrivateKeyParameter(dHPrivateKey), generatePrivateKeyParameter(this.dheParameters.getEphemeralPrivateKey())));
            }
        } else if (algorithmParameterSpec instanceof MQVParameterSpec) {
            if (this.mqvAgreement == null) {
                throw new InvalidAlgorithmParameterException("agreement algorithm not MQV based");
            }
            this.f595p = dHPrivateKey.getParams().getP();
            this.f596g = dHPrivateKey.getParams().getG();
            this.mqvParameters = (MQVParameterSpec) algorithmParameterSpec;
            this.ukmParameters = ((MQVParameterSpec) algorithmParameterSpec).getUserKeyingMaterial();
            if (this.mqvParameters.getEphemeralPublicKey() != null) {
                this.mqvAgreement.init(new DHMQVPrivateParameters(generatePrivateKeyParameter(dHPrivateKey), generatePrivateKeyParameter(this.mqvParameters.getEphemeralPrivateKey()), generatePublicKeyParameter(this.mqvParameters.getEphemeralPublicKey())));
            } else {
                this.mqvAgreement.init(new DHMQVPrivateParameters(generatePrivateKeyParameter(dHPrivateKey), generatePrivateKeyParameter(this.mqvParameters.getEphemeralPrivateKey())));
            }
        } else if (!(algorithmParameterSpec instanceof UserKeyingMaterialSpec)) {
            throw new InvalidAlgorithmParameterException("DHKeyAgreement only accepts DHParameterSpec");
        } else {
            if (this.kdf == null) {
                throw new InvalidAlgorithmParameterException("no KDF specified for UserKeyingMaterialSpec");
            }
            this.f595p = dHPrivateKey.getParams().getP();
            this.f596g = dHPrivateKey.getParams().getG();
            this.dheParameters = null;
            this.ukmParameters = ((UserKeyingMaterialSpec) algorithmParameterSpec).getUserKeyingMaterial();
        }
        this.f594x = dHPrivateKey.getX();
        this.result = bigIntToBytes(this.f594x);
    }

    @Override // javax.crypto.KeyAgreementSpi
    protected void engineInit(Key key, SecureRandom secureRandom) throws InvalidKeyException {
        if (!(key instanceof DHPrivateKey)) {
            throw new InvalidKeyException("DHKeyAgreement requires DHPrivateKey");
        }
        DHPrivateKey dHPrivateKey = (DHPrivateKey) key;
        this.f595p = dHPrivateKey.getParams().getP();
        this.f596g = dHPrivateKey.getParams().getG();
        this.f594x = dHPrivateKey.getX();
        this.result = bigIntToBytes(this.f594x);
    }

    @Override // org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi
    protected byte[] calcSecret() {
        return this.result;
    }

    private DHPrivateKeyParameters generatePrivateKeyParameter(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey instanceof DHPrivateKey) {
            if (privateKey instanceof BCDHPrivateKey) {
                return ((BCDHPrivateKey) privateKey).engineGetKeyParameters();
            }
            DHPrivateKey dHPrivateKey = (DHPrivateKey) privateKey;
            DHParameterSpec params = dHPrivateKey.getParams();
            return new DHPrivateKeyParameters(dHPrivateKey.getX(), new DHParameters(params.getP(), params.getG(), null, params.getL()));
        }
        throw new InvalidKeyException("private key not a DHPrivateKey");
    }

    private DHPublicKeyParameters generatePublicKeyParameter(PublicKey publicKey) throws InvalidKeyException {
        if (publicKey instanceof DHPublicKey) {
            if (publicKey instanceof BCDHPublicKey) {
                return ((BCDHPublicKey) publicKey).engineGetKeyParameters();
            }
            DHPublicKey dHPublicKey = (DHPublicKey) publicKey;
            DHParameterSpec params = dHPublicKey.getParams();
            return params instanceof DHDomainParameterSpec ? new DHPublicKeyParameters(dHPublicKey.getY(), ((DHDomainParameterSpec) params).getDomainParameters()) : new DHPublicKeyParameters(dHPublicKey.getY(), new DHParameters(params.getP(), params.getG(), null, params.getL()));
        }
        throw new InvalidKeyException("public key not a DHPublicKey");
    }
}