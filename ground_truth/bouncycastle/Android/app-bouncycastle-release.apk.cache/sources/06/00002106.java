package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
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
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;

/* loaded from: classes2.dex */
public class KeyPairGeneratorSpi extends java.security.KeyPairGeneratorSpi {
    private static final int Ed25519 = 1;
    private static final int Ed448 = 2;
    private static final int EdDSA = -1;
    private static final int X25519 = 3;
    private static final int X448 = 4;
    private static final int XDH = -2;
    private final int algorithmDeclared;
    private int algorithmInitialized;
    private AsymmetricCipherKeyPairGenerator generator;
    private SecureRandom secureRandom;

    /* loaded from: classes2.dex */
    public static final class Ed25519 extends KeyPairGeneratorSpi {
        public Ed25519() {
            super(1);
        }
    }

    /* loaded from: classes2.dex */
    public static final class Ed448 extends KeyPairGeneratorSpi {
        public Ed448() {
            super(2);
        }
    }

    /* loaded from: classes2.dex */
    public static final class EdDSA extends KeyPairGeneratorSpi {
        public EdDSA() {
            super(-1);
        }
    }

    /* loaded from: classes2.dex */
    public static final class X25519 extends KeyPairGeneratorSpi {
        public X25519() {
            super(3);
        }
    }

    /* loaded from: classes2.dex */
    public static final class X448 extends KeyPairGeneratorSpi {
        public X448() {
            super(4);
        }
    }

    /* loaded from: classes2.dex */
    public static final class XDH extends KeyPairGeneratorSpi {
        public XDH() {
            super(-2);
        }
    }

    KeyPairGeneratorSpi(int i) {
        this.algorithmDeclared = i;
        if (getAlgorithmFamily(i) != i) {
            this.algorithmInitialized = i;
        }
    }

    private static int getAlgorithmFamily(int i) {
        if (i == 1 || i == 2) {
            return -1;
        }
        if (i == 3 || i == 4) {
            return -2;
        }
        return i;
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

    private int getAlgorithmForStrength(int i) {
        if (i == 255 || i == 256) {
            int i2 = this.algorithmDeclared;
            if (i2 != -2) {
                if (i2 == -1 || i2 == 1) {
                    return 1;
                }
                if (i2 != 3) {
                    throw new InvalidParameterException("key size not configurable");
                }
            }
            return 3;
        } else if (i == 448) {
            int i3 = this.algorithmDeclared;
            if (i3 != -2) {
                if (i3 == -1 || i3 == 2) {
                    return 2;
                }
                if (i3 != 4) {
                    throw new InvalidParameterException("key size not configurable");
                }
            }
            return 4;
        } else {
            throw new InvalidParameterException("unknown key size");
        }
    }

    private static String getNameFromParams(AlgorithmParameterSpec algorithmParameterSpec) throws InvalidAlgorithmParameterException {
        return algorithmParameterSpec instanceof ECGenParameterSpec ? ((ECGenParameterSpec) algorithmParameterSpec).getName() : algorithmParameterSpec instanceof ECNamedCurveGenParameterSpec ? ((ECNamedCurveGenParameterSpec) algorithmParameterSpec).getName() : algorithmParameterSpec instanceof EdDSAParameterSpec ? ((EdDSAParameterSpec) algorithmParameterSpec).getCurveName() : algorithmParameterSpec instanceof XDHParameterSpec ? ((XDHParameterSpec) algorithmParameterSpec).getCurveName() : ECUtil.getNameFrom(algorithmParameterSpec);
    }

    private AsymmetricCipherKeyPairGenerator setupGenerator() {
        if (this.secureRandom == null) {
            this.secureRandom = CryptoServicesRegistrar.getSecureRandom();
        }
        int i = this.algorithmInitialized;
        if (i == 1) {
            Ed25519KeyPairGenerator ed25519KeyPairGenerator = new Ed25519KeyPairGenerator();
            ed25519KeyPairGenerator.init(new Ed25519KeyGenerationParameters(this.secureRandom));
            return ed25519KeyPairGenerator;
        } else if (i == 2) {
            Ed448KeyPairGenerator ed448KeyPairGenerator = new Ed448KeyPairGenerator();
            ed448KeyPairGenerator.init(new Ed448KeyGenerationParameters(this.secureRandom));
            return ed448KeyPairGenerator;
        } else if (i == 3) {
            X25519KeyPairGenerator x25519KeyPairGenerator = new X25519KeyPairGenerator();
            x25519KeyPairGenerator.init(new X25519KeyGenerationParameters(this.secureRandom));
            return x25519KeyPairGenerator;
        } else if (i == 4) {
            X448KeyPairGenerator x448KeyPairGenerator = new X448KeyPairGenerator();
            x448KeyPairGenerator.init(new X448KeyGenerationParameters(this.secureRandom));
            return x448KeyPairGenerator;
        } else {
            throw new IllegalStateException("generator not correctly initialized");
        }
    }

    @Override // java.security.KeyPairGeneratorSpi
    public KeyPair generateKeyPair() {
        if (this.algorithmInitialized != 0) {
            if (this.generator == null) {
                this.generator = setupGenerator();
            }
            AsymmetricCipherKeyPair generateKeyPair = this.generator.generateKeyPair();
            int i = this.algorithmInitialized;
            if (i == 1 || i == 2) {
                return new KeyPair(new BCEdDSAPublicKey(generateKeyPair.getPublic()), new BCEdDSAPrivateKey(generateKeyPair.getPrivate()));
            }
            if (i == 3 || i == 4) {
                return new KeyPair(new BCXDHPublicKey(generateKeyPair.getPublic()), new BCXDHPrivateKey(generateKeyPair.getPrivate()));
            }
            throw new IllegalStateException("generator not correctly initialized");
        }
        throw new IllegalStateException("generator not correctly initialized");
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
        if (nameFromParams == null) {
            throw new InvalidAlgorithmParameterException("invalid parameterSpec: " + algorithmParameterSpec);
        }
        int algorithmForName = getAlgorithmForName(nameFromParams);
        int i = this.algorithmDeclared;
        if (i != algorithmForName && i != getAlgorithmFamily(algorithmForName)) {
            throw new InvalidAlgorithmParameterException("parameterSpec for wrong curve type");
        }
        this.algorithmInitialized = algorithmForName;
        this.secureRandom = secureRandom;
        this.generator = null;
    }
}