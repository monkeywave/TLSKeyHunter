package org.bouncycastle.jcajce.provider.asymmetric.compositesignatures;

import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;

/* loaded from: classes2.dex */
public abstract class CompositeSignaturesConstants {
    public static final HashMap<ASN1ObjectIdentifier, CompositeName> ASN1IdentifierAlgorithmNameMap;
    public static final HashMap<ASN1ObjectIdentifier, CompositeName> ASN1IdentifierCompositeNameMap;
    public static final HashMap<CompositeName, ASN1ObjectIdentifier> compositeNameASN1IdentifierMap;
    public static final ASN1ObjectIdentifier[] supportedIdentifiers = {MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256, MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256, MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512, MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, MiscObjectIdentifiers.id_MLDSA44_ECDSA_brainpoolP256r1_SHA256, MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512, MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512, MiscObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512, MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512, MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512, MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512, MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512, MiscObjectIdentifiers.id_MLDSA87_Ed448_SHA512, MiscObjectIdentifiers.id_Falcon512_ECDSA_P256_SHA256, MiscObjectIdentifiers.id_Falcon512_ECDSA_brainpoolP256r1_SHA256, MiscObjectIdentifiers.id_Falcon512_Ed25519_SHA512};

    /* loaded from: classes2.dex */
    public enum CompositeName {
        MLDSA44_RSA2048_PSS_SHA256("MLDSA44-RSA2048-PSS-SHA256"),
        MLDSA44_RSA2048_PKCS15_SHA256("MLDSA44-RSA2048-PKCS15-SHA256"),
        MLDSA44_Ed25519_SHA512("MLDSA44-Ed25519-SHA512"),
        MLDSA44_ECDSA_P256_SHA256("MLDSA44-ECDSA-P256-SHA256"),
        MLDSA44_ECDSA_brainpoolP256r1_SHA256("MLDSA44-ECDSA-brainpoolP256r1-SHA256"),
        MLDSA65_RSA3072_PSS_SHA512("MLDSA65-RSA3072-PSS-SHA512"),
        MLDSA65_RSA3072_PKCS15_SHA512("MLDSA65-RSA3072-PKCS15-SHA512"),
        MLDSA65_ECDSA_brainpoolP256r1_SHA512("MLDSA65-ECDSA-brainpoolP256r1-SHA512"),
        MLDSA65_ECDSA_P256_SHA512("MLDSA65-ECDSA-P256-SHA512"),
        MLDSA65_Ed25519_SHA512("MLDSA65-Ed25519-SHA512"),
        MLDSA87_ECDSA_P384_SHA512("MLDSA87-ECDSA-P384-SHA512"),
        MLDSA87_ECDSA_brainpoolP384r1_SHA512("MLDSA87-ECDSA-brainpoolP384r1-SHA512"),
        MLDSA87_Ed448_SHA512("MLDSA87-Ed448-SHA512"),
        Falcon512_ECDSA_P256_SHA256("Falcon512-ECDSA-P256-SHA256"),
        Falcon512_ECDSA_brainpoolP256r1_SHA256("Falcon512-ECDSA-brainpoolP256r1-SHA256"),
        Falcon512_Ed25519_SHA512("Falcon512-Ed25519-SHA512");
        

        /* renamed from: id */
        private final String f914id;

        CompositeName(String str) {
            this.f914id = str;
        }

        public String getId() {
            return this.f914id;
        }
    }

    static {
        ASN1ObjectIdentifier[] aSN1ObjectIdentifierArr;
        HashMap<CompositeName, ASN1ObjectIdentifier> hashMap = new HashMap<>();
        compositeNameASN1IdentifierMap = hashMap;
        hashMap.put(CompositeName.MLDSA44_RSA2048_PSS_SHA256, MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256);
        hashMap.put(CompositeName.MLDSA44_RSA2048_PKCS15_SHA256, MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256);
        hashMap.put(CompositeName.MLDSA44_ECDSA_P256_SHA256, MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256);
        hashMap.put(CompositeName.MLDSA44_ECDSA_brainpoolP256r1_SHA256, MiscObjectIdentifiers.id_MLDSA44_ECDSA_brainpoolP256r1_SHA256);
        hashMap.put(CompositeName.MLDSA44_Ed25519_SHA512, MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512);
        hashMap.put(CompositeName.MLDSA65_RSA3072_PSS_SHA512, MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512);
        hashMap.put(CompositeName.MLDSA65_RSA3072_PKCS15_SHA512, MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512);
        hashMap.put(CompositeName.MLDSA65_ECDSA_P256_SHA512, MiscObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512);
        hashMap.put(CompositeName.MLDSA65_ECDSA_brainpoolP256r1_SHA512, MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512);
        hashMap.put(CompositeName.MLDSA65_Ed25519_SHA512, MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512);
        hashMap.put(CompositeName.MLDSA87_ECDSA_P384_SHA512, MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512);
        hashMap.put(CompositeName.MLDSA87_ECDSA_brainpoolP384r1_SHA512, MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512);
        hashMap.put(CompositeName.MLDSA87_Ed448_SHA512, MiscObjectIdentifiers.id_MLDSA87_Ed448_SHA512);
        hashMap.put(CompositeName.Falcon512_ECDSA_P256_SHA256, MiscObjectIdentifiers.id_Falcon512_ECDSA_P256_SHA256);
        hashMap.put(CompositeName.Falcon512_ECDSA_brainpoolP256r1_SHA256, MiscObjectIdentifiers.id_Falcon512_ECDSA_brainpoolP256r1_SHA256);
        hashMap.put(CompositeName.Falcon512_Ed25519_SHA512, MiscObjectIdentifiers.id_Falcon512_Ed25519_SHA512);
        ASN1IdentifierCompositeNameMap = new HashMap<>();
        for (Map.Entry<CompositeName, ASN1ObjectIdentifier> entry : hashMap.entrySet()) {
            ASN1IdentifierCompositeNameMap.put(entry.getValue(), entry.getKey());
        }
        ASN1IdentifierAlgorithmNameMap = new HashMap<>();
        for (ASN1ObjectIdentifier aSN1ObjectIdentifier : supportedIdentifiers) {
            ASN1IdentifierAlgorithmNameMap.put(aSN1ObjectIdentifier, ASN1IdentifierCompositeNameMap.get(aSN1ObjectIdentifier));
        }
    }

    private CompositeSignaturesConstants() {
    }
}