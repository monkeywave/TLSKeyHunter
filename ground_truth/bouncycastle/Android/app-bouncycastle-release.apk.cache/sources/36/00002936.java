package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.p006bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.legacy.crypto.gmss.GMSSKeyPairGenerator;
import org.bouncycastle.pqc.legacy.crypto.mceliece.McElieceFujisakiCipher;
import org.bouncycastle.pqc.legacy.crypto.mceliece.McElieceKobaraImaiCipher;
import org.bouncycastle.pqc.legacy.crypto.mceliece.McEliecePointchevalCipher;

/* loaded from: classes2.dex */
public interface PQCObjectIdentifiers {
    public static final ASN1ObjectIdentifier gmss;
    public static final ASN1ObjectIdentifier gmssWithSha1;
    public static final ASN1ObjectIdentifier gmssWithSha224;
    public static final ASN1ObjectIdentifier gmssWithSha256;
    public static final ASN1ObjectIdentifier gmssWithSha384;
    public static final ASN1ObjectIdentifier gmssWithSha512;
    public static final ASN1ObjectIdentifier id_Dilithium3_ECDSA_P256_SHA256;
    public static final ASN1ObjectIdentifier id_Dilithium3_ECDSA_brainpoolP256r1_SHA256;
    public static final ASN1ObjectIdentifier id_Dilithium3_Ed25519;
    public static final ASN1ObjectIdentifier id_Dilithium3_RSA_PKCS15_SHA256;
    public static final ASN1ObjectIdentifier id_Dilithium5_ECDSA_P384_SHA384;
    public static final ASN1ObjectIdentifier id_Dilithium5_ECDSA_brainpoolP384r1_SHA384;
    public static final ASN1ObjectIdentifier id_Dilithium5_Ed448;
    public static final ASN1ObjectIdentifier id_Falcon512_ECDSA_P256_SHA256;
    public static final ASN1ObjectIdentifier id_Falcon512_ECDSA_brainpoolP256r1_SHA256;
    public static final ASN1ObjectIdentifier id_Falcon512_Ed25519;
    public static final ASN1ObjectIdentifier mcEliece;
    public static final ASN1ObjectIdentifier mcElieceCca2;
    public static final ASN1ObjectIdentifier mcElieceFujisaki;
    public static final ASN1ObjectIdentifier mcElieceKobara_Imai;
    public static final ASN1ObjectIdentifier mcEliecePointcheval;
    public static final ASN1ObjectIdentifier newHope;
    public static final ASN1ObjectIdentifier qTESLA;
    public static final ASN1ObjectIdentifier qTESLA_p_I;
    public static final ASN1ObjectIdentifier qTESLA_p_III;
    public static final ASN1ObjectIdentifier rainbow;
    public static final ASN1ObjectIdentifier rainbowWithSha1;
    public static final ASN1ObjectIdentifier rainbowWithSha224;
    public static final ASN1ObjectIdentifier rainbowWithSha256;
    public static final ASN1ObjectIdentifier rainbowWithSha384;
    public static final ASN1ObjectIdentifier rainbowWithSha512;
    public static final ASN1ObjectIdentifier sphincs256;
    public static final ASN1ObjectIdentifier sphincs256_with_BLAKE512;
    public static final ASN1ObjectIdentifier sphincs256_with_SHA3_512;
    public static final ASN1ObjectIdentifier sphincs256_with_SHA512;
    public static final ASN1ObjectIdentifier xmss;
    public static final ASN1ObjectIdentifier xmss_SHA256;
    public static final ASN1ObjectIdentifier xmss_SHA256ph;
    public static final ASN1ObjectIdentifier xmss_SHA512;
    public static final ASN1ObjectIdentifier xmss_SHA512ph;
    public static final ASN1ObjectIdentifier xmss_SHAKE128;
    public static final ASN1ObjectIdentifier xmss_SHAKE128ph;
    public static final ASN1ObjectIdentifier xmss_SHAKE256;
    public static final ASN1ObjectIdentifier xmss_SHAKE256ph;
    public static final ASN1ObjectIdentifier xmss_mt;
    public static final ASN1ObjectIdentifier xmss_mt_SHA256;
    public static final ASN1ObjectIdentifier xmss_mt_SHA256ph;
    public static final ASN1ObjectIdentifier xmss_mt_SHA512;
    public static final ASN1ObjectIdentifier xmss_mt_SHA512ph;
    public static final ASN1ObjectIdentifier xmss_mt_SHAKE128;
    public static final ASN1ObjectIdentifier xmss_mt_SHAKE128ph;
    public static final ASN1ObjectIdentifier xmss_mt_SHAKE256;
    public static final ASN1ObjectIdentifier xmss_mt_SHAKE256ph;
    public static final ASN1ObjectIdentifier xmss_mt_with_SHA256;
    public static final ASN1ObjectIdentifier xmss_mt_with_SHA512;
    public static final ASN1ObjectIdentifier xmss_mt_with_SHAKE128;
    public static final ASN1ObjectIdentifier xmss_mt_with_SHAKE256;
    public static final ASN1ObjectIdentifier xmss_with_SHA256;
    public static final ASN1ObjectIdentifier xmss_with_SHA512;
    public static final ASN1ObjectIdentifier xmss_with_SHAKE128;
    public static final ASN1ObjectIdentifier xmss_with_SHAKE256;

    static {
        ASN1ObjectIdentifier aSN1ObjectIdentifier = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.5.3.2");
        rainbow = aSN1ObjectIdentifier;
        rainbowWithSha1 = aSN1ObjectIdentifier.branch("1");
        rainbowWithSha224 = aSN1ObjectIdentifier.branch("2");
        rainbowWithSha256 = aSN1ObjectIdentifier.branch("3");
        rainbowWithSha384 = aSN1ObjectIdentifier.branch("4");
        rainbowWithSha512 = aSN1ObjectIdentifier.branch("5");
        ASN1ObjectIdentifier aSN1ObjectIdentifier2 = new ASN1ObjectIdentifier(GMSSKeyPairGenerator.OID);
        gmss = aSN1ObjectIdentifier2;
        gmssWithSha1 = aSN1ObjectIdentifier2.branch("1");
        gmssWithSha224 = aSN1ObjectIdentifier2.branch("2");
        gmssWithSha256 = aSN1ObjectIdentifier2.branch("3");
        gmssWithSha384 = aSN1ObjectIdentifier2.branch("4");
        gmssWithSha512 = aSN1ObjectIdentifier2.branch("5");
        mcEliece = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.1");
        mcElieceCca2 = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.2");
        mcElieceFujisaki = new ASN1ObjectIdentifier(McElieceFujisakiCipher.OID);
        mcEliecePointcheval = new ASN1ObjectIdentifier(McEliecePointchevalCipher.OID);
        mcElieceKobara_Imai = new ASN1ObjectIdentifier(McElieceKobaraImaiCipher.OID);
        sphincs256 = BCObjectIdentifiers.sphincs256;
        sphincs256_with_BLAKE512 = BCObjectIdentifiers.sphincs256_with_BLAKE512;
        sphincs256_with_SHA512 = BCObjectIdentifiers.sphincs256_with_SHA512;
        sphincs256_with_SHA3_512 = BCObjectIdentifiers.sphincs256_with_SHA3_512;
        newHope = BCObjectIdentifiers.newHope;
        xmss = BCObjectIdentifiers.xmss;
        ASN1ObjectIdentifier aSN1ObjectIdentifier3 = BCObjectIdentifiers.xmss_SHA256ph;
        xmss_SHA256ph = aSN1ObjectIdentifier3;
        ASN1ObjectIdentifier aSN1ObjectIdentifier4 = BCObjectIdentifiers.xmss_SHA512ph;
        xmss_SHA512ph = aSN1ObjectIdentifier4;
        ASN1ObjectIdentifier aSN1ObjectIdentifier5 = BCObjectIdentifiers.xmss_SHAKE128ph;
        xmss_SHAKE128ph = aSN1ObjectIdentifier5;
        ASN1ObjectIdentifier aSN1ObjectIdentifier6 = BCObjectIdentifiers.xmss_SHAKE256ph;
        xmss_SHAKE256ph = aSN1ObjectIdentifier6;
        xmss_SHA256 = BCObjectIdentifiers.xmss_SHA256;
        xmss_SHA512 = BCObjectIdentifiers.xmss_SHA512;
        xmss_SHAKE128 = BCObjectIdentifiers.xmss_SHAKE128;
        xmss_SHAKE256 = BCObjectIdentifiers.xmss_SHAKE256;
        xmss_mt = BCObjectIdentifiers.xmss_mt;
        ASN1ObjectIdentifier aSN1ObjectIdentifier7 = BCObjectIdentifiers.xmss_mt_SHA256ph;
        xmss_mt_SHA256ph = aSN1ObjectIdentifier7;
        ASN1ObjectIdentifier aSN1ObjectIdentifier8 = BCObjectIdentifiers.xmss_mt_SHA512ph;
        xmss_mt_SHA512ph = aSN1ObjectIdentifier8;
        ASN1ObjectIdentifier aSN1ObjectIdentifier9 = BCObjectIdentifiers.xmss_mt_SHAKE128ph;
        xmss_mt_SHAKE128ph = aSN1ObjectIdentifier9;
        ASN1ObjectIdentifier aSN1ObjectIdentifier10 = BCObjectIdentifiers.xmss_mt_SHAKE256ph;
        xmss_mt_SHAKE256ph = aSN1ObjectIdentifier10;
        xmss_mt_SHA256 = BCObjectIdentifiers.xmss_mt_SHA256;
        xmss_mt_SHA512 = BCObjectIdentifiers.xmss_mt_SHA512;
        xmss_mt_SHAKE128 = BCObjectIdentifiers.xmss_mt_SHAKE128;
        xmss_mt_SHAKE256 = BCObjectIdentifiers.xmss_mt_SHAKE256;
        xmss_with_SHA256 = aSN1ObjectIdentifier3;
        xmss_with_SHA512 = aSN1ObjectIdentifier4;
        xmss_with_SHAKE128 = aSN1ObjectIdentifier5;
        xmss_with_SHAKE256 = aSN1ObjectIdentifier6;
        xmss_mt_with_SHA256 = aSN1ObjectIdentifier7;
        xmss_mt_with_SHA512 = aSN1ObjectIdentifier8;
        xmss_mt_with_SHAKE128 = aSN1ObjectIdentifier9;
        xmss_mt_with_SHAKE256 = aSN1ObjectIdentifier10;
        qTESLA = BCObjectIdentifiers.qTESLA;
        qTESLA_p_I = BCObjectIdentifiers.qTESLA_p_I;
        qTESLA_p_III = BCObjectIdentifiers.qTESLA_p_III;
        id_Dilithium3_RSA_PKCS15_SHA256 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.5.1.1");
        id_Dilithium3_ECDSA_P256_SHA256 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.5.1.2");
        id_Dilithium3_ECDSA_brainpoolP256r1_SHA256 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.5.1.3");
        id_Dilithium3_Ed25519 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.5.1.4");
        id_Dilithium5_ECDSA_P384_SHA384 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.5.1.5");
        id_Dilithium5_ECDSA_brainpoolP384r1_SHA384 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.5.1.6");
        id_Dilithium5_Ed448 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.5.1.7");
        id_Falcon512_ECDSA_P256_SHA256 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.5.1.8");
        id_Falcon512_ECDSA_brainpoolP256r1_SHA256 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.5.1.9");
        id_Falcon512_Ed25519 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.5.1.10");
    }
}