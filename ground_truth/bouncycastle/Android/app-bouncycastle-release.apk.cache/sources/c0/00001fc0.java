package org.bouncycastle.jcajce.provider.asymmetric.compositesignatures;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.p006bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.p009x9.X962Parameters;
import org.bouncycastle.asn1.p009x9.X9ObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeSignaturesConstants;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Exceptions;

/* loaded from: classes2.dex */
public class KeyFactorySpi extends BaseKeyFactorySpi {
    private static final AlgorithmIdentifier dilithium2Identifier = new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_44);
    private static final AlgorithmIdentifier dilithium3Identifier = new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_65);
    private static final AlgorithmIdentifier dilithium5Identifier = new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_87);
    private static final AlgorithmIdentifier falcon512Identifier = new AlgorithmIdentifier(BCObjectIdentifiers.falcon_512);
    private static final AlgorithmIdentifier ed25519Identifier = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519);
    private static final AlgorithmIdentifier ecdsaP256Identifier = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(SECObjectIdentifiers.secp256r1));
    private static final AlgorithmIdentifier ecdsaBrainpoolP256r1Identifier = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(TeleTrusTObjectIdentifiers.brainpoolP256r1));
    private static final AlgorithmIdentifier rsaIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption);
    private static final AlgorithmIdentifier ed448Identifier = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448);
    private static final AlgorithmIdentifier ecdsaP384Identifier = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(SECObjectIdentifiers.secp384r1));
    private static final AlgorithmIdentifier ecdsaBrainpoolP384r1Identifier = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(TeleTrusTObjectIdentifiers.brainpoolP384r1));

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi$1 */
    /* loaded from: classes2.dex */
    public static /* synthetic */ class C12351 {

        /* renamed from: $SwitchMap$org$bouncycastle$jcajce$provider$asymmetric$compositesignatures$CompositeSignaturesConstants$CompositeName */
        static final /* synthetic */ int[] f915x775b5928;

        static {
            int[] iArr = new int[CompositeSignaturesConstants.CompositeName.values().length];
            f915x775b5928 = iArr;
            try {
                iArr[CompositeSignaturesConstants.CompositeName.MLDSA44_Ed25519_SHA512.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f915x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA65_Ed25519_SHA512.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f915x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA87_Ed448_SHA512.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                f915x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA44_RSA2048_PSS_SHA256.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                f915x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA44_RSA2048_PKCS15_SHA256.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                f915x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA65_RSA3072_PSS_SHA512.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                f915x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA65_RSA3072_PKCS15_SHA512.ordinal()] = 7;
            } catch (NoSuchFieldError unused7) {
            }
            try {
                f915x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA44_ECDSA_P256_SHA256.ordinal()] = 8;
            } catch (NoSuchFieldError unused8) {
            }
            try {
                f915x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA44_ECDSA_brainpoolP256r1_SHA256.ordinal()] = 9;
            } catch (NoSuchFieldError unused9) {
            }
            try {
                f915x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA65_ECDSA_P256_SHA512.ordinal()] = 10;
            } catch (NoSuchFieldError unused10) {
            }
            try {
                f915x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA65_ECDSA_brainpoolP256r1_SHA512.ordinal()] = 11;
            } catch (NoSuchFieldError unused11) {
            }
            try {
                f915x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA87_ECDSA_P384_SHA512.ordinal()] = 12;
            } catch (NoSuchFieldError unused12) {
            }
            try {
                f915x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA87_ECDSA_brainpoolP384r1_SHA512.ordinal()] = 13;
            } catch (NoSuchFieldError unused13) {
            }
            try {
                f915x775b5928[CompositeSignaturesConstants.CompositeName.Falcon512_Ed25519_SHA512.ordinal()] = 14;
            } catch (NoSuchFieldError unused14) {
            }
            try {
                f915x775b5928[CompositeSignaturesConstants.CompositeName.Falcon512_ECDSA_P256_SHA256.ordinal()] = 15;
            } catch (NoSuchFieldError unused15) {
            }
            try {
                f915x775b5928[CompositeSignaturesConstants.CompositeName.Falcon512_ECDSA_brainpoolP256r1_SHA256.ordinal()] = 16;
            } catch (NoSuchFieldError unused16) {
            }
        }
    }

    private List<KeyFactory> getKeyFactoriesFromIdentifier(ASN1ObjectIdentifier aSN1ObjectIdentifier) throws NoSuchAlgorithmException, NoSuchProviderException {
        String str;
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        switch (C12351.f915x775b5928[CompositeSignaturesConstants.ASN1IdentifierCompositeNameMap.get(aSN1ObjectIdentifier).ordinal()]) {
            case 1:
            case 2:
                arrayList2.add("ML-DSA");
                arrayList2.add(EdDSAParameterSpec.Ed25519);
                arrayList.add(KeyFactory.getInstance((String) arrayList2.get(0), BouncyCastleProvider.PROVIDER_NAME));
                arrayList.add(KeyFactory.getInstance((String) arrayList2.get(1), BouncyCastleProvider.PROVIDER_NAME));
                return Collections.unmodifiableList(arrayList);
            case 3:
                arrayList2.add("ML-DSA");
                str = EdDSAParameterSpec.Ed448;
                arrayList2.add(str);
                arrayList.add(KeyFactory.getInstance((String) arrayList2.get(0), BouncyCastleProvider.PROVIDER_NAME));
                arrayList.add(KeyFactory.getInstance((String) arrayList2.get(1), BouncyCastleProvider.PROVIDER_NAME));
                return Collections.unmodifiableList(arrayList);
            case 4:
            case 5:
            case 6:
            case 7:
                arrayList2.add("ML-DSA");
                str = "RSA";
                arrayList2.add(str);
                arrayList.add(KeyFactory.getInstance((String) arrayList2.get(0), BouncyCastleProvider.PROVIDER_NAME));
                arrayList.add(KeyFactory.getInstance((String) arrayList2.get(1), BouncyCastleProvider.PROVIDER_NAME));
                return Collections.unmodifiableList(arrayList);
            case 8:
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
                arrayList2.add("ML-DSA");
                arrayList2.add("ECDSA");
                arrayList.add(KeyFactory.getInstance((String) arrayList2.get(0), BouncyCastleProvider.PROVIDER_NAME));
                arrayList.add(KeyFactory.getInstance((String) arrayList2.get(1), BouncyCastleProvider.PROVIDER_NAME));
                return Collections.unmodifiableList(arrayList);
            case 14:
                arrayList2.add("Falcon");
                arrayList2.add(EdDSAParameterSpec.Ed25519);
                arrayList.add(KeyFactory.getInstance((String) arrayList2.get(0), BouncyCastleProvider.PROVIDER_NAME));
                arrayList.add(KeyFactory.getInstance((String) arrayList2.get(1), BouncyCastleProvider.PROVIDER_NAME));
                return Collections.unmodifiableList(arrayList);
            case 15:
            case 16:
                arrayList2.add("Falcon");
                arrayList2.add("ECDSA");
                arrayList.add(KeyFactory.getInstance((String) arrayList2.get(0), BouncyCastleProvider.PROVIDER_NAME));
                arrayList.add(KeyFactory.getInstance((String) arrayList2.get(1), BouncyCastleProvider.PROVIDER_NAME));
                return Collections.unmodifiableList(arrayList);
            default:
                throw new IllegalArgumentException("Cannot create KeyFactories. Unsupported algorithm identifier.");
        }
    }

    private X509EncodedKeySpec[] getKeysSpecs(ASN1ObjectIdentifier aSN1ObjectIdentifier, ASN1BitString[] aSN1BitStringArr) throws IOException {
        X509EncodedKeySpec[] x509EncodedKeySpecArr = new X509EncodedKeySpec[aSN1BitStringArr.length];
        SubjectPublicKeyInfo[] subjectPublicKeyInfoArr = new SubjectPublicKeyInfo[aSN1BitStringArr.length];
        switch (C12351.f915x775b5928[CompositeSignaturesConstants.ASN1IdentifierCompositeNameMap.get(aSN1ObjectIdentifier).ordinal()]) {
            case 1:
                subjectPublicKeyInfoArr[0] = new SubjectPublicKeyInfo(dilithium2Identifier, aSN1BitStringArr[0]);
                subjectPublicKeyInfoArr[1] = new SubjectPublicKeyInfo(ed25519Identifier, aSN1BitStringArr[1]);
                break;
            case 2:
                subjectPublicKeyInfoArr[0] = new SubjectPublicKeyInfo(dilithium3Identifier, aSN1BitStringArr[0]);
                subjectPublicKeyInfoArr[1] = new SubjectPublicKeyInfo(ed25519Identifier, aSN1BitStringArr[1]);
                break;
            case 3:
                subjectPublicKeyInfoArr[0] = new SubjectPublicKeyInfo(dilithium5Identifier, aSN1BitStringArr[0]);
                subjectPublicKeyInfoArr[1] = new SubjectPublicKeyInfo(ed448Identifier, aSN1BitStringArr[1]);
                break;
            case 4:
            case 5:
                subjectPublicKeyInfoArr[0] = new SubjectPublicKeyInfo(dilithium2Identifier, aSN1BitStringArr[0]);
                subjectPublicKeyInfoArr[1] = new SubjectPublicKeyInfo(rsaIdentifier, aSN1BitStringArr[1]);
                break;
            case 6:
            case 7:
                subjectPublicKeyInfoArr[0] = new SubjectPublicKeyInfo(dilithium3Identifier, aSN1BitStringArr[0]);
                subjectPublicKeyInfoArr[1] = new SubjectPublicKeyInfo(rsaIdentifier, aSN1BitStringArr[1]);
                break;
            case 8:
                subjectPublicKeyInfoArr[0] = new SubjectPublicKeyInfo(dilithium2Identifier, aSN1BitStringArr[0]);
                subjectPublicKeyInfoArr[1] = new SubjectPublicKeyInfo(ecdsaP256Identifier, aSN1BitStringArr[1]);
                break;
            case 9:
                subjectPublicKeyInfoArr[0] = new SubjectPublicKeyInfo(dilithium2Identifier, aSN1BitStringArr[0]);
                subjectPublicKeyInfoArr[1] = new SubjectPublicKeyInfo(ecdsaBrainpoolP256r1Identifier, aSN1BitStringArr[1]);
                break;
            case 10:
                subjectPublicKeyInfoArr[0] = new SubjectPublicKeyInfo(dilithium3Identifier, aSN1BitStringArr[0]);
                subjectPublicKeyInfoArr[1] = new SubjectPublicKeyInfo(ecdsaP256Identifier, aSN1BitStringArr[1]);
                break;
            case 11:
                subjectPublicKeyInfoArr[0] = new SubjectPublicKeyInfo(dilithium3Identifier, aSN1BitStringArr[0]);
                subjectPublicKeyInfoArr[1] = new SubjectPublicKeyInfo(ecdsaBrainpoolP256r1Identifier, aSN1BitStringArr[1]);
                break;
            case 12:
                subjectPublicKeyInfoArr[0] = new SubjectPublicKeyInfo(dilithium5Identifier, aSN1BitStringArr[0]);
                subjectPublicKeyInfoArr[1] = new SubjectPublicKeyInfo(ecdsaP384Identifier, aSN1BitStringArr[1]);
                break;
            case 13:
                subjectPublicKeyInfoArr[0] = new SubjectPublicKeyInfo(dilithium5Identifier, aSN1BitStringArr[0]);
                subjectPublicKeyInfoArr[1] = new SubjectPublicKeyInfo(ecdsaBrainpoolP384r1Identifier, aSN1BitStringArr[1]);
                break;
            case 14:
                subjectPublicKeyInfoArr[0] = new SubjectPublicKeyInfo(falcon512Identifier, aSN1BitStringArr[0]);
                subjectPublicKeyInfoArr[1] = new SubjectPublicKeyInfo(ed25519Identifier, aSN1BitStringArr[1]);
                break;
            case 15:
                subjectPublicKeyInfoArr[0] = new SubjectPublicKeyInfo(falcon512Identifier, aSN1BitStringArr[0]);
                subjectPublicKeyInfoArr[1] = new SubjectPublicKeyInfo(ecdsaP256Identifier, aSN1BitStringArr[1]);
                break;
            case 16:
                subjectPublicKeyInfoArr[0] = new SubjectPublicKeyInfo(falcon512Identifier, aSN1BitStringArr[0]);
                subjectPublicKeyInfoArr[1] = new SubjectPublicKeyInfo(ecdsaBrainpoolP256r1Identifier, aSN1BitStringArr[1]);
                break;
            default:
                throw new IllegalArgumentException("Cannot create key specs. Unsupported algorithm identifier.");
        }
        x509EncodedKeySpecArr[0] = new X509EncodedKeySpec(subjectPublicKeyInfoArr[0].getEncoded());
        x509EncodedKeySpecArr[1] = new X509EncodedKeySpec(subjectPublicKeyInfoArr[1].getEncoded());
        return x509EncodedKeySpecArr;
    }

    @Override // java.security.KeyFactorySpi
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        try {
            if (key instanceof PrivateKey) {
                return generatePrivate(PrivateKeyInfo.getInstance(key.getEncoded()));
            }
            if (key instanceof PublicKey) {
                return generatePublic(SubjectPublicKeyInfo.getInstance(key.getEncoded()));
            }
            throw new InvalidKeyException("Key not recognized");
        } catch (IOException e) {
            throw new InvalidKeyException("Key could not be parsed: " + e.getMessage());
        }
    }

    @Override // org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter
    public PrivateKey generatePrivate(PrivateKeyInfo privateKeyInfo) throws IOException {
        ASN1Sequence dERSequence = DERSequence.getInstance(privateKeyInfo.parsePrivateKey());
        ASN1ObjectIdentifier algorithm = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm();
        try {
            List<KeyFactory> keyFactoriesFromIdentifier = getKeyFactoriesFromIdentifier(algorithm);
            PrivateKey[] privateKeyArr = new PrivateKey[dERSequence.size()];
            for (int i = 0; i < dERSequence.size(); i++) {
                ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(dERSequence.getObjectAt(i));
                if (aSN1Sequence.size() == 2) {
                    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
                    aSN1EncodableVector.add(privateKeyInfo.getVersion());
                    aSN1EncodableVector.add(aSN1Sequence.getObjectAt(0));
                    aSN1EncodableVector.add(aSN1Sequence.getObjectAt(1));
                    privateKeyArr[i] = keyFactoriesFromIdentifier.get(i).generatePrivate(new PKCS8EncodedKeySpec(PrivateKeyInfo.getInstance(new DERSequence(aSN1EncodableVector)).getEncoded()));
                } else {
                    privateKeyArr[i] = keyFactoriesFromIdentifier.get(i).generatePrivate(new PKCS8EncodedKeySpec(PrivateKeyInfo.getInstance(aSN1Sequence).getEncoded()));
                }
            }
            return new CompositePrivateKey(algorithm, privateKeyArr);
        } catch (GeneralSecurityException e) {
            throw Exceptions.ioException(e.getMessage(), e);
        }
    }

    @Override // org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter
    public PublicKey generatePublic(SubjectPublicKeyInfo subjectPublicKeyInfo) throws IOException {
        ASN1Sequence dERSequence = DERSequence.getInstance(subjectPublicKeyInfo.getPublicKeyData().getBytes());
        ASN1ObjectIdentifier algorithm = subjectPublicKeyInfo.getAlgorithm().getAlgorithm();
        try {
            List<KeyFactory> keyFactoriesFromIdentifier = getKeyFactoriesFromIdentifier(algorithm);
            ASN1BitString[] aSN1BitStringArr = new ASN1BitString[dERSequence.size()];
            for (int i = 0; i < dERSequence.size(); i++) {
                if (dERSequence.getObjectAt(i) instanceof DEROctetString) {
                    aSN1BitStringArr[i] = new DERBitString(((DEROctetString) dERSequence.getObjectAt(i)).getOctets());
                } else {
                    aSN1BitStringArr[i] = (DERBitString) dERSequence.getObjectAt(i);
                }
            }
            X509EncodedKeySpec[] keysSpecs = getKeysSpecs(algorithm, aSN1BitStringArr);
            PublicKey[] publicKeyArr = new PublicKey[dERSequence.size()];
            for (int i2 = 0; i2 < dERSequence.size(); i2++) {
                publicKeyArr[i2] = keyFactoriesFromIdentifier.get(i2).generatePublic(keysSpecs[i2]);
            }
            return new CompositePublicKey(algorithm, publicKeyArr);
        } catch (GeneralSecurityException e) {
            throw Exceptions.ioException(e.getMessage(), e);
        }
    }
}