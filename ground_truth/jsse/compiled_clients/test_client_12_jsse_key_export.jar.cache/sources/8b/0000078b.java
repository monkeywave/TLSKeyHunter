package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X448KeyGenerationParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/edec/KeyPairGeneratorSpi.class */
public class KeyPairGeneratorSpi extends java.security.KeyPairGeneratorSpi {
    private static final int EdDSA = -1;
    private static final int XDH = -2;
    private static final int Ed25519 = 1;
    private static final int Ed448 = 2;
    private static final int X25519 = 3;
    private static final int X448 = 4;
    private final int algorithmDeclared;
    private int algorithmInitialized;
    private SecureRandom secureRandom;
    private AsymmetricCipherKeyPairGenerator generator;

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/edec/KeyPairGeneratorSpi$Ed25519.class */
    public static final class Ed25519 extends KeyPairGeneratorSpi {
        public Ed25519() {
            super(1);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/edec/KeyPairGeneratorSpi$Ed448.class */
    public static final class Ed448 extends KeyPairGeneratorSpi {
        public Ed448() {
            super(2);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/edec/KeyPairGeneratorSpi$EdDSA.class */
    public static final class EdDSA extends KeyPairGeneratorSpi {
        public EdDSA() {
            super(KeyPairGeneratorSpi.EdDSA);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/edec/KeyPairGeneratorSpi$X25519.class */
    public static final class X25519 extends KeyPairGeneratorSpi {
        public X25519() {
            super(3);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/edec/KeyPairGeneratorSpi$X448.class */
    public static final class X448 extends KeyPairGeneratorSpi {
        public X448() {
            super(4);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/edec/KeyPairGeneratorSpi$XDH.class */
    public static final class XDH extends KeyPairGeneratorSpi {
        public XDH() {
            super(KeyPairGeneratorSpi.XDH);
        }
    }

    KeyPairGeneratorSpi(int i) {
        this.algorithmDeclared = i;
        if (getAlgorithmFamily(i) != i) {
            this.algorithmInitialized = i;
        }
    }

    @Override // java.security.KeyPairGeneratorSpi
    public void initialize(int i, SecureRandom secureRandom) {
        this.algorithmInitialized = getAlgorithmForStrength(i);
        this.secureRandom = secureRandom;
        this.generator = null;
    }

    @Override // java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        String nameFromParams = getNameFromParams(algorithmParameterSpec);
        if (null == nameFromParams) {
            throw new InvalidAlgorithmParameterException("invalid parameterSpec: " + algorithmParameterSpec);
        }
        int algorithmForName = getAlgorithmForName(nameFromParams);
        if (this.algorithmDeclared != algorithmForName && this.algorithmDeclared != getAlgorithmFamily(algorithmForName)) {
            throw new InvalidAlgorithmParameterException("parameterSpec for wrong curve type");
        }
        this.algorithmInitialized = algorithmForName;
        this.secureRandom = secureRandom;
        this.generator = null;
    }

    @Override // java.security.KeyPairGeneratorSpi
    public KeyPair generateKeyPair() {
        if (this.algorithmInitialized == 0) {
            throw new IllegalStateException("generator not correctly initialized");
        }
        if (null == this.generator) {
            this.generator = setupGenerator();
        }
        AsymmetricCipherKeyPair generateKeyPair = this.generator.generateKeyPair();
        switch (this.algorithmInitialized) {
            case 1:
            case 2:
                return new KeyPair(new BCEdDSAPublicKey(generateKeyPair.getPublic()), new BCEdDSAPrivateKey(generateKeyPair.getPrivate()));
            case 3:
            case 4:
                return new KeyPair(new BCXDHPublicKey(generateKeyPair.getPublic()), new BCXDHPrivateKey(generateKeyPair.getPrivate()));
            default:
                throw new IllegalStateException("generator not correctly initialized");
        }
    }

    private int getAlgorithmForStrength(int i) {
        switch (i) {
            case GF2Field.MASK /* 255 */:
            case 256:
                switch (this.algorithmDeclared) {
                    case XDH /* -2 */:
                    case 3:
                        return 3;
                    case EdDSA /* -1 */:
                    case 1:
                        return 1;
                    case 0:
                    case 2:
                    default:
                        throw new InvalidParameterException("key size not configurable");
                }
            case 448:
                switch (this.algorithmDeclared) {
                    case XDH /* -2 */:
                    case 4:
                        return 4;
                    case EdDSA /* -1 */:
                    case 2:
                        return 2;
                    case 0:
                    case 1:
                    case 3:
                    default:
                        throw new InvalidParameterException("key size not configurable");
                }
            default:
                throw new InvalidParameterException("unknown key size");
        }
    }

    private AsymmetricCipherKeyPairGenerator setupGenerator() {
        if (null == this.secureRandom) {
            this.secureRandom = CryptoServicesRegistrar.getSecureRandom();
        }
        switch (this.algorithmInitialized) {
            case 1:
                Ed25519KeyPairGenerator ed25519KeyPairGenerator = new Ed25519KeyPairGenerator();
                ed25519KeyPairGenerator.init(new Ed25519KeyGenerationParameters(this.secureRandom));
                return ed25519KeyPairGenerator;
            case 2:
                Ed448KeyPairGenerator ed448KeyPairGenerator = new Ed448KeyPairGenerator();
                ed448KeyPairGenerator.init(new Ed448KeyGenerationParameters(this.secureRandom));
                return ed448KeyPairGenerator;
            case 3:
                X25519KeyPairGenerator x25519KeyPairGenerator = new X25519KeyPairGenerator();
                x25519KeyPairGenerator.init(new X25519KeyGenerationParameters(this.secureRandom));
                return x25519KeyPairGenerator;
            case 4:
                X448KeyPairGenerator x448KeyPairGenerator = new X448KeyPairGenerator();
                x448KeyPairGenerator.init(new X448KeyGenerationParameters(this.secureRandom));
                return x448KeyPairGenerator;
            default:
                throw new IllegalStateException("generator not correctly initialized");
        }
    }

    private static int getAlgorithmFamily(int i) {
        switch (i) {
            case 1:
            case 2:
                return EdDSA;
            case 3:
            case 4:
                return XDH;
            default:
                return i;
        }
    }

    private static int getAlgorithmForName(String str) throws InvalidAlgorithmParameterException {
        if (str.equalsIgnoreCase(XDHParameterSpec.X25519) || str.equals(EdECObjectIdentifiers.id_X25519.getId())) {
            return 3;
        }
        if (str.equalsIgnoreCase(EdDSAParameterSpec.Ed25519) || str.equals(EdECObjectIdentifiers.id_Ed25519.getId())) {
            return 1;
        }
        if (str.equalsIgnoreCase(XDHParameterSpec.X448) || str.equals(EdECObjectIdentifiers.id_X448.getId())) {
            return 4;
        }
        if (str.equalsIgnoreCase(EdDSAParameterSpec.Ed448) || str.equals(EdECObjectIdentifiers.id_Ed448.getId())) {
            return 2;
        }
        throw new InvalidAlgorithmParameterException("invalid parameterSpec name: " + str);
    }

    private static String getNameFromParams(AlgorithmParameterSpec algorithmParameterSpec) throws InvalidAlgorithmParameterException {
        return algorithmParameterSpec instanceof ECGenParameterSpec ? ((ECGenParameterSpec) algorithmParameterSpec).getName() : algorithmParameterSpec instanceof ECNamedCurveGenParameterSpec ? ((ECNamedCurveGenParameterSpec) algorithmParameterSpec).getName() : algorithmParameterSpec instanceof EdDSAParameterSpec ? ((EdDSAParameterSpec) algorithmParameterSpec).getCurveName() : algorithmParameterSpec instanceof XDHParameterSpec ? ((XDHParameterSpec) algorithmParameterSpec).getCurveName() : ECUtil.getNameFrom(algorithmParameterSpec);
    }
}