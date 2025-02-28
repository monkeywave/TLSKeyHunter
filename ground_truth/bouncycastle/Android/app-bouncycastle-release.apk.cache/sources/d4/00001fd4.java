package org.bouncycastle.jcajce.provider.asymmetric.compositesignatures;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeSignaturesConstants;
import org.bouncycastle.jcajce.spec.CompositeAlgorithmSpec;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Exceptions;

/* loaded from: classes2.dex */
public class SignatureSpi extends java.security.SignatureSpi {
    private static final String ML_DSA_44 = "ML-DSA-44";
    private static final String ML_DSA_65 = "ML-DSA-65";
    private static final String ML_DSA_87 = "ML-DSA-87";
    private static final Map<String, String> canonicalNames;
    private byte[] OIDBytes;
    private final CompositeSignaturesConstants.CompositeName algorithmIdentifier;
    private final ASN1ObjectIdentifier algorithmIdentifierASN1;
    private final List<Signature> componentSignatures;
    private final Digest digest;

    /* renamed from: org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.SignatureSpi$1 */
    /* loaded from: classes2.dex */
    static /* synthetic */ class C12371 {

        /* renamed from: $SwitchMap$org$bouncycastle$jcajce$provider$asymmetric$compositesignatures$CompositeSignaturesConstants$CompositeName */
        static final /* synthetic */ int[] f917x775b5928;

        static {
            int[] iArr = new int[CompositeSignaturesConstants.CompositeName.values().length];
            f917x775b5928 = iArr;
            try {
                iArr[CompositeSignaturesConstants.CompositeName.MLDSA44_Ed25519_SHA512.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f917x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA65_Ed25519_SHA512.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f917x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA87_Ed448_SHA512.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                f917x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA44_RSA2048_PSS_SHA256.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                f917x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA65_RSA3072_PSS_SHA512.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                f917x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA44_RSA2048_PKCS15_SHA256.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                f917x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA65_RSA3072_PKCS15_SHA512.ordinal()] = 7;
            } catch (NoSuchFieldError unused7) {
            }
            try {
                f917x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA44_ECDSA_P256_SHA256.ordinal()] = 8;
            } catch (NoSuchFieldError unused8) {
            }
            try {
                f917x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA44_ECDSA_brainpoolP256r1_SHA256.ordinal()] = 9;
            } catch (NoSuchFieldError unused9) {
            }
            try {
                f917x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA65_ECDSA_P256_SHA512.ordinal()] = 10;
            } catch (NoSuchFieldError unused10) {
            }
            try {
                f917x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA65_ECDSA_brainpoolP256r1_SHA512.ordinal()] = 11;
            } catch (NoSuchFieldError unused11) {
            }
            try {
                f917x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA87_ECDSA_P384_SHA512.ordinal()] = 12;
            } catch (NoSuchFieldError unused12) {
            }
            try {
                f917x775b5928[CompositeSignaturesConstants.CompositeName.MLDSA87_ECDSA_brainpoolP384r1_SHA512.ordinal()] = 13;
            } catch (NoSuchFieldError unused13) {
            }
            try {
                f917x775b5928[CompositeSignaturesConstants.CompositeName.Falcon512_ECDSA_P256_SHA256.ordinal()] = 14;
            } catch (NoSuchFieldError unused14) {
            }
            try {
                f917x775b5928[CompositeSignaturesConstants.CompositeName.Falcon512_ECDSA_brainpoolP256r1_SHA256.ordinal()] = 15;
            } catch (NoSuchFieldError unused15) {
            }
            try {
                f917x775b5928[CompositeSignaturesConstants.CompositeName.Falcon512_Ed25519_SHA512.ordinal()] = 16;
            } catch (NoSuchFieldError unused16) {
            }
        }
    }

    /* loaded from: classes2.dex */
    public static final class Falcon512_ECDSA_P256_SHA256 extends SignatureSpi {
        public Falcon512_ECDSA_P256_SHA256() {
            super(CompositeSignaturesConstants.CompositeName.Falcon512_ECDSA_P256_SHA256);
        }
    }

    /* loaded from: classes2.dex */
    public static final class Falcon512_ECDSA_brainpoolP256r1_SHA256 extends SignatureSpi {
        public Falcon512_ECDSA_brainpoolP256r1_SHA256() {
            super(CompositeSignaturesConstants.CompositeName.Falcon512_ECDSA_brainpoolP256r1_SHA256);
        }
    }

    /* loaded from: classes2.dex */
    public static final class Falcon512_Ed25519_SHA512 extends SignatureSpi {
        public Falcon512_Ed25519_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.Falcon512_Ed25519_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA44_ECDSA_P256_SHA256 extends SignatureSpi {
        public MLDSA44_ECDSA_P256_SHA256() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_ECDSA_P256_SHA256);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA44_ECDSA_brainpoolP256r1_SHA256 extends SignatureSpi {
        public MLDSA44_ECDSA_brainpoolP256r1_SHA256() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_ECDSA_brainpoolP256r1_SHA256);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA44_Ed25519_SHA512 extends SignatureSpi {
        public MLDSA44_Ed25519_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_Ed25519_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA44_RSA2048_PKCS15_SHA256 extends SignatureSpi {
        public MLDSA44_RSA2048_PKCS15_SHA256() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_RSA2048_PKCS15_SHA256);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA44_RSA2048_PSS_SHA256 extends SignatureSpi {
        public MLDSA44_RSA2048_PSS_SHA256() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_RSA2048_PSS_SHA256);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA65_ECDSA_P256_SHA512 extends SignatureSpi {
        public MLDSA65_ECDSA_P256_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_ECDSA_P256_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA65_ECDSA_brainpoolP256r1_SHA512 extends SignatureSpi {
        public MLDSA65_ECDSA_brainpoolP256r1_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_ECDSA_brainpoolP256r1_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA65_Ed25519_SHA512 extends SignatureSpi {
        public MLDSA65_Ed25519_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_Ed25519_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA65_RSA3072_PKCS15_SHA512 extends SignatureSpi {
        public MLDSA65_RSA3072_PKCS15_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_RSA3072_PKCS15_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA65_RSA3072_PSS_SHA512 extends SignatureSpi {
        public MLDSA65_RSA3072_PSS_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_RSA3072_PSS_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA87_ECDSA_P384_SHA512 extends SignatureSpi {
        public MLDSA87_ECDSA_P384_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA87_ECDSA_P384_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA87_ECDSA_brainpoolP384r1_SHA512 extends SignatureSpi {
        public MLDSA87_ECDSA_brainpoolP384r1_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA87_ECDSA_brainpoolP384r1_SHA512);
        }
    }

    /* loaded from: classes2.dex */
    public static final class MLDSA87_Ed448_SHA512 extends SignatureSpi {
        public MLDSA87_Ed448_SHA512() {
            super(CompositeSignaturesConstants.CompositeName.MLDSA87_Ed448_SHA512);
        }
    }

    static {
        HashMap hashMap = new HashMap();
        canonicalNames = hashMap;
        hashMap.put("MLDSA44", ML_DSA_44);
        hashMap.put("MLDSA65", ML_DSA_65);
        hashMap.put("MLDSA87", ML_DSA_87);
        hashMap.put(NISTObjectIdentifiers.id_ml_dsa_44.getId(), ML_DSA_44);
        hashMap.put(NISTObjectIdentifiers.id_ml_dsa_65.getId(), ML_DSA_65);
        hashMap.put(NISTObjectIdentifiers.id_ml_dsa_87.getId(), ML_DSA_87);
    }

    SignatureSpi(CompositeSignaturesConstants.CompositeName compositeName) {
        Digest createSHA512;
        this.algorithmIdentifier = compositeName;
        ASN1ObjectIdentifier aSN1ObjectIdentifier = CompositeSignaturesConstants.compositeNameASN1IdentifierMap.get(compositeName);
        this.algorithmIdentifierASN1 = aSN1ObjectIdentifier;
        ArrayList arrayList = new ArrayList();
        try {
            switch (C12371.f917x775b5928[compositeName.ordinal()]) {
                case 1:
                    arrayList.add(Signature.getInstance(ML_DSA_44, BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(Signature.getInstance(EdDSAParameterSpec.Ed25519, BouncyCastleProvider.PROVIDER_NAME));
                    createSHA512 = DigestFactory.createSHA512();
                    break;
                case 2:
                    arrayList.add(Signature.getInstance(ML_DSA_65, BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(Signature.getInstance(EdDSAParameterSpec.Ed25519, BouncyCastleProvider.PROVIDER_NAME));
                    createSHA512 = DigestFactory.createSHA512();
                    break;
                case 3:
                    arrayList.add(Signature.getInstance(ML_DSA_87, BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(Signature.getInstance(EdDSAParameterSpec.Ed448, BouncyCastleProvider.PROVIDER_NAME));
                    createSHA512 = DigestFactory.createSHA512();
                    break;
                case 4:
                    arrayList.add(Signature.getInstance(ML_DSA_44, BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(Signature.getInstance("SHA256withRSA/PSS", BouncyCastleProvider.PROVIDER_NAME));
                    createSHA512 = DigestFactory.createSHA256();
                    break;
                case 5:
                    arrayList.add(Signature.getInstance(ML_DSA_65, BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(Signature.getInstance("SHA512withRSA/PSS", BouncyCastleProvider.PROVIDER_NAME));
                    createSHA512 = DigestFactory.createSHA512();
                    break;
                case 6:
                    arrayList.add(Signature.getInstance(ML_DSA_44, BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME));
                    createSHA512 = DigestFactory.createSHA256();
                    break;
                case 7:
                    arrayList.add(Signature.getInstance(ML_DSA_65, BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(Signature.getInstance("SHA512withRSA", BouncyCastleProvider.PROVIDER_NAME));
                    createSHA512 = DigestFactory.createSHA512();
                    break;
                case 8:
                case 9:
                    arrayList.add(Signature.getInstance(ML_DSA_44, BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME));
                    createSHA512 = DigestFactory.createSHA256();
                    break;
                case 10:
                case 11:
                    arrayList.add(Signature.getInstance(ML_DSA_65, BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(Signature.getInstance("SHA512withECDSA", BouncyCastleProvider.PROVIDER_NAME));
                    createSHA512 = DigestFactory.createSHA512();
                    break;
                case 12:
                case 13:
                    arrayList.add(Signature.getInstance(ML_DSA_87, BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(Signature.getInstance("SHA512withECDSA", BouncyCastleProvider.PROVIDER_NAME));
                    createSHA512 = DigestFactory.createSHA512();
                    break;
                case 14:
                case 15:
                    arrayList.add(Signature.getInstance("Falcon", BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME));
                    createSHA512 = DigestFactory.createSHA256();
                    break;
                case 16:
                    arrayList.add(Signature.getInstance("Falcon", BouncyCastleProvider.PROVIDER_NAME));
                    arrayList.add(Signature.getInstance(EdDSAParameterSpec.Ed25519, BouncyCastleProvider.PROVIDER_NAME));
                    createSHA512 = DigestFactory.createSHA512();
                    break;
                default:
                    throw new IllegalArgumentException("unknown composite algorithm");
            }
            this.digest = createSHA512;
            this.OIDBytes = aSN1ObjectIdentifier.getEncoded(ASN1Encoding.DER);
            this.componentSignatures = Collections.unmodifiableList(arrayList);
        } catch (IOException e) {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        } catch (GeneralSecurityException e2) {
            throw Exceptions.illegalStateException(e2.getMessage(), e2);
        }
    }

    private String getCanonicalName(String str) {
        String str2 = canonicalNames.get(str);
        return str2 != null ? str2 : str;
    }

    private void setSigParameter(Signature signature, String str, List<String> list, List<AlgorithmParameterSpec> list2) throws InvalidAlgorithmParameterException {
        for (int i = 0; i != list.size(); i++) {
            getCanonicalName(list.get(i));
            if (list.get(i).equals(str)) {
                signature.setParameter(list2.get(i));
            }
        }
    }

    @Override // java.security.SignatureSpi
    protected Object engineGetParameter(String str) throws InvalidParameterException {
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }

    @Override // java.security.SignatureSpi
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override // java.security.SignatureSpi
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof CompositePrivateKey)) {
            throw new InvalidKeyException("Private key is not composite.");
        }
        CompositePrivateKey compositePrivateKey = (CompositePrivateKey) privateKey;
        if (!compositePrivateKey.getAlgorithmIdentifier().equals((ASN1Primitive) this.algorithmIdentifierASN1)) {
            throw new InvalidKeyException("Provided composite private key cannot be used with the composite signature algorithm.");
        }
        for (int i = 0; i < this.componentSignatures.size(); i++) {
            this.componentSignatures.get(i).initSign(compositePrivateKey.getPrivateKeys().get(i));
        }
    }

    @Override // java.security.SignatureSpi
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof CompositePublicKey)) {
            throw new InvalidKeyException("Public key is not composite.");
        }
        CompositePublicKey compositePublicKey = (CompositePublicKey) publicKey;
        if (!compositePublicKey.getAlgorithmIdentifier().equals((ASN1Primitive) this.algorithmIdentifierASN1)) {
            throw new InvalidKeyException("Provided composite public key cannot be used with the composite signature algorithm.");
        }
        for (int i = 0; i < this.componentSignatures.size(); i++) {
            this.componentSignatures.get(i).initVerify(compositePublicKey.getPublicKeys().get(i));
        }
    }

    @Override // java.security.SignatureSpi
    protected void engineSetParameter(String str, Object obj) throws InvalidParameterException {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    @Override // java.security.SignatureSpi
    protected void engineSetParameter(AlgorithmParameterSpec algorithmParameterSpec) throws InvalidAlgorithmParameterException {
        if (!(algorithmParameterSpec instanceof CompositeAlgorithmSpec)) {
            throw new InvalidAlgorithmParameterException("unknown parameterSpec passed to composite signature");
        }
        CompositeAlgorithmSpec compositeAlgorithmSpec = (CompositeAlgorithmSpec) algorithmParameterSpec;
        List<AlgorithmParameterSpec> parameterSpecs = compositeAlgorithmSpec.getParameterSpecs();
        List<String> algorithmNames = compositeAlgorithmSpec.getAlgorithmNames();
        switch (C12371.f917x775b5928[this.algorithmIdentifier.ordinal()]) {
            case 1:
            case 4:
            case 6:
            case 8:
            case 9:
                setSigParameter(this.componentSignatures.get(0), ML_DSA_44, algorithmNames, parameterSpecs);
                return;
            case 2:
            case 5:
            case 7:
            case 10:
            case 11:
                setSigParameter(this.componentSignatures.get(0), ML_DSA_65, algorithmNames, parameterSpecs);
                return;
            case 3:
            case 12:
            case 13:
                setSigParameter(this.componentSignatures.get(0), ML_DSA_87, algorithmNames, parameterSpecs);
                return;
            default:
                throw new InvalidAlgorithmParameterException("unknown composite algorithm");
        }
    }

    @Override // java.security.SignatureSpi
    protected byte[] engineSign() throws SignatureException {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        try {
            byte[] bArr = new byte[this.digest.getDigestSize()];
            this.digest.doFinal(bArr, 0);
            for (int i = 0; i < this.componentSignatures.size(); i++) {
                this.componentSignatures.get(i).update(this.OIDBytes);
                this.componentSignatures.get(i).update(bArr);
                aSN1EncodableVector.add(new DERBitString(this.componentSignatures.get(i).sign()));
            }
            return new DERSequence(aSN1EncodableVector).getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new SignatureException(e.getMessage());
        }
    }

    @Override // java.security.SignatureSpi
    protected void engineUpdate(byte b) throws SignatureException {
        this.digest.update(b);
    }

    @Override // java.security.SignatureSpi
    protected void engineUpdate(byte[] bArr, int i, int i2) throws SignatureException {
        this.digest.update(bArr, i, i2);
    }

    @Override // java.security.SignatureSpi
    protected boolean engineVerify(byte[] bArr) throws SignatureException {
        ASN1Sequence dERSequence = DERSequence.getInstance(bArr);
        if (dERSequence.size() != this.componentSignatures.size()) {
            return false;
        }
        byte[] bArr2 = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(bArr2, 0);
        boolean z = false;
        for (int i = 0; i < this.componentSignatures.size(); i++) {
            this.componentSignatures.get(i).update(this.OIDBytes);
            this.componentSignatures.get(i).update(bArr2);
            if (!this.componentSignatures.get(i).verify(ASN1BitString.getInstance(dERSequence.getObjectAt(i)).getOctets())) {
                z = true;
            }
        }
        return !z;
    }
}