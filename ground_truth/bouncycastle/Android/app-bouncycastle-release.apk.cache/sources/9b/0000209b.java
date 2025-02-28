package org.bouncycastle.jcajce.provider.asymmetric.p014ec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Hashtable;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.p009x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMEngine;
import org.bouncycastle.util.Integers;

/* renamed from: org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi */
/* loaded from: classes2.dex */
public abstract class KeyPairGeneratorSpi extends KeyPairGenerator {

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$EC */
    /* loaded from: classes2.dex */
    public static class C1245EC extends KeyPairGeneratorSpi {
        private static Hashtable ecParameters;
        String algorithm;
        ProviderConfiguration configuration;
        Object ecParams;
        ECKeyPairGenerator engine;
        boolean initialised;
        ECKeyGenerationParameters param;
        SecureRandom random;
        int strength;

        static {
            Hashtable hashtable = new Hashtable();
            ecParameters = hashtable;
            hashtable.put(Integers.valueOf(192), new ECGenParameterSpec("prime192v1"));
            ecParameters.put(Integers.valueOf(239), new ECGenParameterSpec("prime239v1"));
            ecParameters.put(Integers.valueOf(256), new ECGenParameterSpec("prime256v1"));
            ecParameters.put(Integers.valueOf(BERTags.FLAGS), new ECGenParameterSpec("P-224"));
            ecParameters.put(Integers.valueOf(MLKEMEngine.KyberPolyBytes), new ECGenParameterSpec("P-384"));
            ecParameters.put(Integers.valueOf(521), new ECGenParameterSpec("P-521"));
        }

        public C1245EC() {
            super("EC");
            this.engine = new ECKeyPairGenerator();
            this.ecParams = null;
            this.strength = 239;
            this.random = CryptoServicesRegistrar.getSecureRandom();
            this.initialised = false;
            this.algorithm = "EC";
            this.configuration = BouncyCastleProvider.CONFIGURATION;
        }

        public C1245EC(String str, ProviderConfiguration providerConfiguration) {
            super(str);
            this.engine = new ECKeyPairGenerator();
            this.ecParams = null;
            this.strength = 239;
            this.random = CryptoServicesRegistrar.getSecureRandom();
            this.initialised = false;
            this.algorithm = str;
            this.configuration = providerConfiguration;
        }

        protected ECKeyGenerationParameters createKeyGenParamsBC(ECParameterSpec eCParameterSpec, SecureRandom secureRandom) {
            return new ECKeyGenerationParameters(new ECDomainParameters(eCParameterSpec.getCurve(), eCParameterSpec.getG(), eCParameterSpec.getN(), eCParameterSpec.getH()), secureRandom);
        }

        protected ECKeyGenerationParameters createKeyGenParamsJCE(java.security.spec.ECParameterSpec eCParameterSpec, SecureRandom secureRandom) {
            X9ECParameters domainParametersFromName;
            if (!(eCParameterSpec instanceof ECNamedCurveSpec) || (domainParametersFromName = ECUtils.getDomainParametersFromName(((ECNamedCurveSpec) eCParameterSpec).getName(), this.configuration)) == null) {
                ECCurve convertCurve = EC5Util.convertCurve(eCParameterSpec.getCurve());
                return new ECKeyGenerationParameters(new ECDomainParameters(convertCurve, EC5Util.convertPoint(convertCurve, eCParameterSpec.getGenerator()), eCParameterSpec.getOrder(), BigInteger.valueOf(eCParameterSpec.getCofactor())), secureRandom);
            }
            return createKeyGenParamsJCE(domainParametersFromName, secureRandom);
        }

        protected ECKeyGenerationParameters createKeyGenParamsJCE(X9ECParameters x9ECParameters, SecureRandom secureRandom) {
            return new ECKeyGenerationParameters(new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN(), x9ECParameters.getH()), secureRandom);
        }

        @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
        public KeyPair generateKeyPair() {
            if (!this.initialised) {
                initialize(this.strength, new SecureRandom());
            }
            AsymmetricCipherKeyPair generateKeyPair = this.engine.generateKeyPair();
            ECPublicKeyParameters eCPublicKeyParameters = (ECPublicKeyParameters) generateKeyPair.getPublic();
            ECPrivateKeyParameters eCPrivateKeyParameters = (ECPrivateKeyParameters) generateKeyPair.getPrivate();
            Object obj = this.ecParams;
            if (obj instanceof ECParameterSpec) {
                ECParameterSpec eCParameterSpec = (ECParameterSpec) obj;
                BCECPublicKey bCECPublicKey = new BCECPublicKey(this.algorithm, eCPublicKeyParameters, eCParameterSpec, this.configuration);
                return new KeyPair(bCECPublicKey, new BCECPrivateKey(this.algorithm, eCPrivateKeyParameters, bCECPublicKey, eCParameterSpec, this.configuration));
            } else if (obj == null) {
                return new KeyPair(new BCECPublicKey(this.algorithm, eCPublicKeyParameters, this.configuration), new BCECPrivateKey(this.algorithm, eCPrivateKeyParameters, this.configuration));
            } else {
                java.security.spec.ECParameterSpec eCParameterSpec2 = (java.security.spec.ECParameterSpec) obj;
                BCECPublicKey bCECPublicKey2 = new BCECPublicKey(this.algorithm, eCPublicKeyParameters, eCParameterSpec2, this.configuration);
                return new KeyPair(bCECPublicKey2, new BCECPrivateKey(this.algorithm, eCPrivateKeyParameters, bCECPublicKey2, eCParameterSpec2, this.configuration));
            }
        }

        @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
        public void initialize(int i, SecureRandom secureRandom) {
            this.strength = i;
            this.random = secureRandom;
            ECGenParameterSpec eCGenParameterSpec = (ECGenParameterSpec) ecParameters.get(Integers.valueOf(i));
            if (eCGenParameterSpec == null) {
                throw new InvalidParameterException("unknown key size.");
            }
            try {
                initialize(eCGenParameterSpec, secureRandom);
            } catch (InvalidAlgorithmParameterException unused) {
                throw new InvalidParameterException("key size not configurable.");
            }
        }

        @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
        public void initialize(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
            String name;
            ECKeyGenerationParameters createKeyGenParamsJCE;
            ECParameterSpec eCParameterSpec;
            if (algorithmParameterSpec == null) {
                eCParameterSpec = this.configuration.getEcImplicitlyCa();
                if (eCParameterSpec == null) {
                    throw new InvalidAlgorithmParameterException("null parameter passed but no implicitCA set");
                }
                this.ecParams = null;
            } else if (!(algorithmParameterSpec instanceof ECParameterSpec)) {
                if (algorithmParameterSpec instanceof java.security.spec.ECParameterSpec) {
                    this.ecParams = algorithmParameterSpec;
                    createKeyGenParamsJCE = createKeyGenParamsJCE((java.security.spec.ECParameterSpec) algorithmParameterSpec, secureRandom);
                    this.param = createKeyGenParamsJCE;
                    this.engine.init(this.param);
                    this.initialised = true;
                }
                if (algorithmParameterSpec instanceof ECGenParameterSpec) {
                    name = ((ECGenParameterSpec) algorithmParameterSpec).getName();
                } else if (!(algorithmParameterSpec instanceof ECNamedCurveGenParameterSpec)) {
                    String nameFrom = ECUtil.getNameFrom(algorithmParameterSpec);
                    if (nameFrom == null) {
                        throw new InvalidAlgorithmParameterException("invalid parameterSpec: " + algorithmParameterSpec);
                    }
                    initializeNamedCurve(nameFrom, secureRandom);
                    this.engine.init(this.param);
                    this.initialised = true;
                } else {
                    name = ((ECNamedCurveGenParameterSpec) algorithmParameterSpec).getName();
                }
                initializeNamedCurve(name, secureRandom);
                this.engine.init(this.param);
                this.initialised = true;
            } else {
                this.ecParams = algorithmParameterSpec;
                eCParameterSpec = (ECParameterSpec) algorithmParameterSpec;
            }
            createKeyGenParamsJCE = createKeyGenParamsBC(eCParameterSpec, secureRandom);
            this.param = createKeyGenParamsJCE;
            this.engine.init(this.param);
            this.initialised = true;
        }

        protected void initializeNamedCurve(String str, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
            X9ECParameters domainParametersFromName = ECUtils.getDomainParametersFromName(str, this.configuration);
            if (domainParametersFromName == null) {
                throw new InvalidAlgorithmParameterException("unknown curve name: " + str);
            }
            this.ecParams = new ECNamedCurveSpec(str, domainParametersFromName.getCurve(), domainParametersFromName.getG(), domainParametersFromName.getN(), domainParametersFromName.getH(), null);
            this.param = createKeyGenParamsJCE(domainParametersFromName, secureRandom);
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$ECDH */
    /* loaded from: classes2.dex */
    public static class ECDH extends C1245EC {
        public ECDH() {
            super("ECDH", BouncyCastleProvider.CONFIGURATION);
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$ECDHC */
    /* loaded from: classes2.dex */
    public static class ECDHC extends C1245EC {
        public ECDHC() {
            super("ECDHC", BouncyCastleProvider.CONFIGURATION);
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$ECDSA */
    /* loaded from: classes2.dex */
    public static class ECDSA extends C1245EC {
        public ECDSA() {
            super("ECDSA", BouncyCastleProvider.CONFIGURATION);
        }
    }

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$ECMQV */
    /* loaded from: classes2.dex */
    public static class ECMQV extends C1245EC {
        public ECMQV() {
            super("ECMQV", BouncyCastleProvider.CONFIGURATION);
        }
    }

    public KeyPairGeneratorSpi(String str) {
        super(str);
    }
}