package org.bouncycastle.jcajce.provider.asymmetric.compositesignatures;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeSignaturesConstants;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

/* loaded from: classes2.dex */
public class KeyPairGeneratorSpi extends java.security.KeyPairGeneratorSpi {
    private final CompositeSignaturesConstants.CompositeName algorithmIdentifier;
    private final ASN1ObjectIdentifier algorithmIdentifierASN1;
    private List<KeyPairGenerator> generators;
    private boolean parametersInitialized = false;
    private SecureRandom secureRandom;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyPairGeneratorSpi$1 */
    /* loaded from: classes2.dex */
    public static /* synthetic */ class C12361 {

        /* renamed from: $SwitchMap$org$bouncycastle$jcajce$provider$asymmetric$compositesignatures$CompositeSignaturesConstants$CompositeName */
        static final /* synthetic */ int[] f916x775b5928;

        static {
            int[] iArr = new int[CompositeSignaturesConstants.CompositeName.values().length];
            f916x775b5928 = iArr;
            try {
                iArr[CompositeSignaturesConstants.CompositeName.MLDSA44_Ed25519_SHA512.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f916x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA65_Ed25519_SHA512.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f916x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA87_Ed448_SHA512.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                f916x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA44_RSA2048_PSS_SHA256.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                f916x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA44_RSA2048_PKCS15_SHA256.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                f916x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA65_RSA3072_PSS_SHA512.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                f916x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA65_RSA3072_PKCS15_SHA512.ordinal()] = 7;
            } catch (NoSuchFieldError unused7) {
            }
            try {
                f916x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA44_ECDSA_P256_SHA256.ordinal()] = 8;
            } catch (NoSuchFieldError unused8) {
            }
            try {
                f916x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA44_ECDSA_brainpoolP256r1_SHA256.ordinal()] = 9;
            } catch (NoSuchFieldError unused9) {
            }
            try {
                f916x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA65_ECDSA_P256_SHA512.ordinal()] = 10;
            } catch (NoSuchFieldError unused10) {
            }
            try {
                f916x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA65_ECDSA_brainpoolP256r1_SHA512.ordinal()] = 11;
            } catch (NoSuchFieldError unused11) {
            }
            try {
                f916x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA87_ECDSA_P384_SHA512.ordinal()] = 12;
            } catch (NoSuchFieldError unused12) {
            }
            try {
                f916x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA87_ECDSA_brainpoolP384r1_SHA512.ordinal()] = 13;
            } catch (NoSuchFieldError unused13) {
            }
            try {
                f916x775b5928[CompositeSignaturesConstants.CompositeName.Falcon512_ECDSA_P256_SHA256.ordinal()] = 14;
            } catch (NoSuchFieldError unused14) {
            }
            try {
                f916x775b5928[CompositeSignaturesConstants.CompositeName.Falcon512_ECDSA_brainpoolP256r1_SHA256.ordinal()] = 15;
            } catch (NoSuchFieldError unused15) {
            }
            try {
                f916x775b5928[CompositeSignaturesConstants.CompositeName.Falcon512_Ed25519_SHA512.ordinal()] = 16;
            } catch (NoSuchFieldError unused16) {
            }
        }
    }

    /* loaded from: classes2.dex */
    public static final class Falcon512_ECDSA_P256_SHA256 extends KeyPairGeneratorSpi {
        public Falcon512_ECDSA_P256_SHA256() {
            super(CompositeSignaturesConstants.CompositeName.Falcon512_ECDSA_P256_SHA256);
        }
    }

    /* loaded from: classes2.dex */
    public static final class Falcon512_ECDSA_brainpoolP256r1_SHA256 extends KeyPairGeneratorSpi {
        public Falcon512_ECDSA_brainpoolP256r1_SHA256() {
            super(CompositeSignaturesConstants.CompositeName.Falcon512_ECDSA_brainpoolP256r1_SHA256);
        }
    }

    /* loaded from: classes2.dex */
    public static final class Falcon512_Ed25519_SHA512 extends KeyPairGeneratorSpi {
        public Falcon512_Ed25519_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.Falcon512_Ed25519_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA44_ECDSA_P256_SHA256 extends KeyPairGeneratorSpi {
        public MLDSA44_ECDSA_P256_SHA256() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_ECDSA_P256_SHA256);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA44_ECDSA_brainpoolP256r1_SHA256 extends KeyPairGeneratorSpi {
        public MLDSA44_ECDSA_brainpoolP256r1_SHA256() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_ECDSA_brainpoolP256r1_SHA256);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA44_Ed25519_SHA512 extends KeyPairGeneratorSpi {
        public MLDSA44_Ed25519_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_Ed25519_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA44_RSA2048_PKCS15_SHA256 extends KeyPairGeneratorSpi {
        public MLDSA44_RSA2048_PKCS15_SHA256() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_RSA2048_PKCS15_SHA256);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA44_RSA2048_PSS_SHA256 extends KeyPairGeneratorSpi {
        public MLDSA44_RSA2048_PSS_SHA256() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_RSA2048_PSS_SHA256);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA65_ECDSA_P256_SHA512 extends KeyPairGeneratorSpi {
        public MLDSA65_ECDSA_P256_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_ECDSA_P256_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA65_ECDSA_brainpoolP256r1_SHA512 extends KeyPairGeneratorSpi {
        public MLDSA65_ECDSA_brainpoolP256r1_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_ECDSA_brainpoolP256r1_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA65_Ed25519_SHA512 extends KeyPairGeneratorSpi {
        public MLDSA65_Ed25519_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_Ed25519_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA65_RSA3072_PKCS15_SHA512 extends KeyPairGeneratorSpi {
        public MLDSA65_RSA3072_PKCS15_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_RSA3072_PKCS15_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA65_RSA3072_PSS_SHA512 extends KeyPairGeneratorSpi {
        public MLDSA65_RSA3072_PSS_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_RSA3072_PSS_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA87_ECDSA_P384_SHA512 extends KeyPairGeneratorSpi {
        public MLDSA87_ECDSA_P384_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA87_ECDSA_P384_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA87_ECDSA_brainpoolP384r1_SHA512 extends KeyPairGeneratorSpi {
        public MLDSA87_ECDSA_brainpoolP384r1_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA87_ECDSA_brainpoolP384r1_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA87_Ed448_SHA512 extends KeyPairGeneratorSpi {
        public MLDSA87_Ed448_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA87_Ed448_SHA512);
        }
    }

    KeyPairGeneratorSpi(CompositeSignaturesConstants.CompositeName compositeName) {
        this.algorithmIdentifier = compositeName;
        this.algorithmIdentifierASN1 = CompositeSignaturesConstants.compositeNameASN1IdentifierMap.get(compositeName);
    }

    private KeyPair getCompositeKeyPair() {
        PublicKey[] publicKeyArr = new PublicKey[this.generators.size()];
        PrivateKey[] privateKeyArr = new PrivateKey[this.generators.size()];
        for (int i = 0; i < this.generators.size(); i++) {
            KeyPair generateKeyPair = this.generators.get(i).generateKeyPair();
            publicKeyArr[i] = generateKeyPair.getPublic();
            privateKeyArr[i] = generateKeyPair.getPrivate();
        }
        return new KeyPair(new CompositePublicKey(this.algorithmIdentifierASN1, publicKeyArr), new CompositePrivateKey(this.algorithmIdentifierASN1, privateKeyArr));
    }

    private void initializeParameters() {
        KeyPairGenerator keyPairGenerator;
        SecureRandom secureRandom;
        KeyPairGenerator keyPairGenerator2;
        ECGenParameterSpec eCGenParameterSpec;
        SecureRandom secureRandom2;
        if (this.secureRandom == null) {
            this.secureRandom = new SecureRandom();
        }
        ArrayList arrayList = new ArrayList();
        try {
            switch (C12361.f916x775b5928[this.algorithmIdentifier.ordinal()]) {
                case 1:
                    arrayList.add(KeyPairGenerator.getInstance("ML-DSA-44", BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(KeyPairGenerator.getInstance(EdDSAParameterSpec.Ed25519, BouncyCastleProvider.PROVIDER_NAME));
                    ((KeyPairGenerator) arrayList.get(0)).initialize(MLDSAParameterSpec.ml_dsa_44, this.secureRandom);
                    keyPairGenerator = (KeyPairGenerator) arrayList.get(1);
                    secureRandom = this.secureRandom;
                    keyPairGenerator.initialize(256, secureRandom);
                    break;
                case 2:
                    arrayList.add(KeyPairGenerator.getInstance("ML-DSA-65", BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(KeyPairGenerator.getInstance(EdDSAParameterSpec.Ed25519, BouncyCastleProvider.PROVIDER_NAME));
                    ((KeyPairGenerator) arrayList.get(0)).initialize(MLDSAParameterSpec.ml_dsa_65, this.secureRandom);
                    keyPairGenerator = (KeyPairGenerator) arrayList.get(1);
                    secureRandom = this.secureRandom;
                    keyPairGenerator.initialize(256, secureRandom);
                    break;
                case 3:
                    arrayList.add(KeyPairGenerator.getInstance("ML-DSA-87", BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(KeyPairGenerator.getInstance(EdDSAParameterSpec.Ed448, BouncyCastleProvider.PROVIDER_NAME));
                    ((KeyPairGenerator) arrayList.get(0)).initialize(MLDSAParameterSpec.ml_dsa_87, this.secureRandom);
                    ((KeyPairGenerator) arrayList.get(1)).initialize(448, this.secureRandom);
                    break;
                case 4:
                case 5:
                    arrayList.add(KeyPairGenerator.getInstance("ML-DSA-44", BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME));
                    ((KeyPairGenerator) arrayList.get(0)).initialize(MLDSAParameterSpec.ml_dsa_44, this.secureRandom);
                    ((KeyPairGenerator) arrayList.get(1)).initialize(2048, this.secureRandom);
                    break;
                case 6:
                case 7:
                    arrayList.add(KeyPairGenerator.getInstance("ML-DSA-65", BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME));
                    ((KeyPairGenerator) arrayList.get(0)).initialize(MLDSAParameterSpec.ml_dsa_65, this.secureRandom);
                    ((KeyPairGenerator) arrayList.get(1)).initialize(3072, this.secureRandom);
                    break;
                case 8:
                    arrayList.add(KeyPairGenerator.getInstance("ML-DSA-44", BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME));
                    ((KeyPairGenerator) arrayList.get(0)).initialize(MLDSAParameterSpec.ml_dsa_44, this.secureRandom);
                    keyPairGenerator2 = (KeyPairGenerator) arrayList.get(1);
                    eCGenParameterSpec = new ECGenParameterSpec("P-256");
                    secureRandom2 = this.secureRandom;
                    keyPairGenerator2.initialize(eCGenParameterSpec, secureRandom2);
                    break;
                case 9:
                    arrayList.add(KeyPairGenerator.getInstance("ML-DSA-44", BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME));
                    ((KeyPairGenerator) arrayList.get(0)).initialize(MLDSAParameterSpec.ml_dsa_44, this.secureRandom);
                    keyPairGenerator2 = (KeyPairGenerator) arrayList.get(1);
                    eCGenParameterSpec = new ECGenParameterSpec("brainpoolP256r1");
                    secureRandom2 = this.secureRandom;
                    keyPairGenerator2.initialize(eCGenParameterSpec, secureRandom2);
                    break;
                case 10:
                    arrayList.add(KeyPairGenerator.getInstance("ML-DSA-65", BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME));
                    ((KeyPairGenerator) arrayList.get(0)).initialize(MLDSAParameterSpec.ml_dsa_65, this.secureRandom);
                    keyPairGenerator2 = (KeyPairGenerator) arrayList.get(1);
                    eCGenParameterSpec = new ECGenParameterSpec("P-256");
                    secureRandom2 = this.secureRandom;
                    keyPairGenerator2.initialize(eCGenParameterSpec, secureRandom2);
                    break;
                case 11:
                    arrayList.add(KeyPairGenerator.getInstance("ML-DSA-65", BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME));
                    ((KeyPairGenerator) arrayList.get(0)).initialize(MLDSAParameterSpec.ml_dsa_65, this.secureRandom);
                    keyPairGenerator2 = (KeyPairGenerator) arrayList.get(1);
                    eCGenParameterSpec = new ECGenParameterSpec("brainpoolP256r1");
                    secureRandom2 = this.secureRandom;
                    keyPairGenerator2.initialize(eCGenParameterSpec, secureRandom2);
                    break;
                case 12:
                    arrayList.add(KeyPairGenerator.getInstance("ML-DSA-87", BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME));
                    ((KeyPairGenerator) arrayList.get(0)).initialize(MLDSAParameterSpec.ml_dsa_87, this.secureRandom);
                    keyPairGenerator2 = (KeyPairGenerator) arrayList.get(1);
                    eCGenParameterSpec = new ECGenParameterSpec("P-384");
                    secureRandom2 = this.secureRandom;
                    keyPairGenerator2.initialize(eCGenParameterSpec, secureRandom2);
                    break;
                case 13:
                    arrayList.add(KeyPairGenerator.getInstance("ML-DSA-87", BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME));
                    ((KeyPairGenerator) arrayList.get(0)).initialize(MLDSAParameterSpec.ml_dsa_87, this.secureRandom);
                    keyPairGenerator2 = (KeyPairGenerator) arrayList.get(1);
                    eCGenParameterSpec = new ECGenParameterSpec("brainpoolP384r1");
                    secureRandom2 = this.secureRandom;
                    keyPairGenerator2.initialize(eCGenParameterSpec, secureRandom2);
                    break;
                case 14:
                    arrayList.add(KeyPairGenerator.getInstance("Falcon", BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME));
                    ((KeyPairGenerator) arrayList.get(0)).initialize(FalconParameterSpec.falcon_512, this.secureRandom);
                    keyPairGenerator2 = (KeyPairGenerator) arrayList.get(1);
                    eCGenParameterSpec = new ECGenParameterSpec("P-256");
                    secureRandom2 = this.secureRandom;
                    keyPairGenerator2.initialize(eCGenParameterSpec, secureRandom2);
                    break;
                case 15:
                    arrayList.add(KeyPairGenerator.getInstance("Falcon", BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME));
                    ((KeyPairGenerator) arrayList.get(0)).initialize(FalconParameterSpec.falcon_512, this.secureRandom);
                    keyPairGenerator2 = (KeyPairGenerator) arrayList.get(1);
                    eCGenParameterSpec = new ECGenParameterSpec("brainpoolP256r1");
                    secureRandom2 = this.secureRandom;
                    keyPairGenerator2.initialize(eCGenParameterSpec, secureRandom2);
                    break;
                case 16:
                    arrayList.add(KeyPairGenerator.getInstance("Falcon", BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(KeyPairGenerator.getInstance(EdDSAParameterSpec.Ed25519, BouncyCastleProvider.PROVIDER_NAME));
                    ((KeyPairGenerator) arrayList.get(0)).initialize(FalconParameterSpec.falcon_512, this.secureRandom);
                    keyPairGenerator = (KeyPairGenerator) arrayList.get(1);
                    secureRandom = this.secureRandom;
                    keyPairGenerator.initialize(256, secureRandom);
                    break;
                default:
                    throw new IllegalStateException("Generators not correctly initialized. Unsupported composite algorithm.");
            }
            this.generators = Collections.unmodifiableList(arrayList);
            this.parametersInitialized = true;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override // java.security.KeyPairGeneratorSpi
    public KeyPair generateKeyPair() {
        if (!this.parametersInitialized) {
            initializeParameters();
        }
        return getCompositeKeyPair();
    }

    @Override // java.security.KeyPairGeneratorSpi
    public void initialize(int i, SecureRandom secureRandom) {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    @Override // java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        if (algorithmParameterSpec != null) {
            throw new IllegalArgumentException("Use initialize only for custom SecureRandom. AlgorithmParameterSpec must be null because it is determined by algorithm name.");
        }
        this.secureRandom = secureRandom;
        initializeParameters();
    }
}