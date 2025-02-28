package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;

/* loaded from: classes.dex */
public interface X509ObjectIdentifiers {
    public static final ASN1ObjectIdentifier attributeType;
    public static final ASN1ObjectIdentifier commonName;
    public static final ASN1ObjectIdentifier countryName;
    public static final ASN1ObjectIdentifier crlAccessMethod;
    public static final ASN1ObjectIdentifier id_PasswordBasedMac;
    public static final ASN1ObjectIdentifier id_SHA1;
    public static final ASN1ObjectIdentifier id_ad;
    public static final ASN1ObjectIdentifier id_ad_caIssuers;
    public static final ASN1ObjectIdentifier id_ad_ocsp;
    public static final ASN1ObjectIdentifier id_at_name;
    public static final ASN1ObjectIdentifier id_at_organizationIdentifier;
    public static final ASN1ObjectIdentifier id_at_telephoneNumber;
    public static final ASN1ObjectIdentifier id_ce;
    public static final ASN1ObjectIdentifier id_ea_rsa;
    public static final ASN1ObjectIdentifier id_ecdsa_with_shake128;
    public static final ASN1ObjectIdentifier id_ecdsa_with_shake256;
    public static final ASN1ObjectIdentifier id_pda;
    public static final ASN1ObjectIdentifier id_pe;
    public static final ASN1ObjectIdentifier id_pkix;
    public static final ASN1ObjectIdentifier id_rsassa_pss_shake128;
    public static final ASN1ObjectIdentifier id_rsassa_pss_shake256;
    public static final ASN1ObjectIdentifier localityName;
    public static final ASN1ObjectIdentifier ocspAccessMethod;
    public static final ASN1ObjectIdentifier organization;
    public static final ASN1ObjectIdentifier organizationalUnitName;
    public static final ASN1ObjectIdentifier pkix_algorithms;
    public static final ASN1ObjectIdentifier ripemd160;
    public static final ASN1ObjectIdentifier ripemd160WithRSAEncryption;
    public static final ASN1ObjectIdentifier stateOrProvinceName;

    static {
        ASN1ObjectIdentifier intern = new ASN1ObjectIdentifier("2.5.4").intern();
        attributeType = intern;
        commonName = intern.branch("3").intern();
        countryName = intern.branch("6").intern();
        localityName = intern.branch("7").intern();
        stateOrProvinceName = intern.branch("8").intern();
        organization = intern.branch("10").intern();
        organizationalUnitName = intern.branch("11").intern();
        id_at_telephoneNumber = intern.branch("20").intern();
        id_at_name = intern.branch("41").intern();
        id_at_organizationIdentifier = intern.branch("97").intern();
        id_SHA1 = new ASN1ObjectIdentifier("1.3.14.3.2.26").intern();
        ripemd160 = new ASN1ObjectIdentifier("1.3.36.3.2.1").intern();
        ripemd160WithRSAEncryption = new ASN1ObjectIdentifier("1.3.36.3.3.1.2").intern();
        id_ea_rsa = new ASN1ObjectIdentifier("2.5.8.1.1").intern();
        ASN1ObjectIdentifier aSN1ObjectIdentifier = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");
        id_pkix = aSN1ObjectIdentifier;
        id_pe = aSN1ObjectIdentifier.branch("1");
        ASN1ObjectIdentifier branch = aSN1ObjectIdentifier.branch("6");
        pkix_algorithms = branch;
        id_rsassa_pss_shake128 = branch.branch("30");
        id_rsassa_pss_shake256 = branch.branch("31");
        id_ecdsa_with_shake128 = branch.branch("32");
        id_ecdsa_with_shake256 = branch.branch("33");
        id_pda = aSN1ObjectIdentifier.branch("9");
        ASN1ObjectIdentifier branch2 = aSN1ObjectIdentifier.branch("48");
        id_ad = branch2;
        ASN1ObjectIdentifier intern2 = branch2.branch("2").intern();
        id_ad_caIssuers = intern2;
        ASN1ObjectIdentifier intern3 = branch2.branch("1").intern();
        id_ad_ocsp = intern3;
        ocspAccessMethod = intern3;
        crlAccessMethod = intern2;
        id_ce = new ASN1ObjectIdentifier("2.5.29");
        id_PasswordBasedMac = MiscObjectIdentifiers.entrust.branch("66.13");
    }
}