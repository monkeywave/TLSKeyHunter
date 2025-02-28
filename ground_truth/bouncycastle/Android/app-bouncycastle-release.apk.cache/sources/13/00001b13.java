package org.bouncycastle.asn1.ocsp;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

/* loaded from: classes.dex */
public interface OCSPObjectIdentifiers {
    public static final ASN1ObjectIdentifier id_pkix_ocsp;
    public static final ASN1ObjectIdentifier id_pkix_ocsp_archive_cutoff;
    public static final ASN1ObjectIdentifier id_pkix_ocsp_basic;
    public static final ASN1ObjectIdentifier id_pkix_ocsp_crl;
    public static final ASN1ObjectIdentifier id_pkix_ocsp_extended_revoke;
    public static final ASN1ObjectIdentifier id_pkix_ocsp_nocheck;
    public static final ASN1ObjectIdentifier id_pkix_ocsp_nonce;
    public static final ASN1ObjectIdentifier id_pkix_ocsp_pref_sig_algs;
    public static final ASN1ObjectIdentifier id_pkix_ocsp_response;
    public static final ASN1ObjectIdentifier id_pkix_ocsp_service_locator;

    static {
        ASN1ObjectIdentifier aSN1ObjectIdentifier = X509ObjectIdentifiers.id_ad_ocsp;
        id_pkix_ocsp = aSN1ObjectIdentifier;
        id_pkix_ocsp_basic = aSN1ObjectIdentifier.branch("1");
        id_pkix_ocsp_nonce = aSN1ObjectIdentifier.branch("2");
        id_pkix_ocsp_crl = aSN1ObjectIdentifier.branch("3");
        id_pkix_ocsp_response = aSN1ObjectIdentifier.branch("4");
        id_pkix_ocsp_nocheck = aSN1ObjectIdentifier.branch("5");
        id_pkix_ocsp_archive_cutoff = aSN1ObjectIdentifier.branch("6");
        id_pkix_ocsp_service_locator = aSN1ObjectIdentifier.branch("7");
        id_pkix_ocsp_pref_sig_algs = aSN1ObjectIdentifier.branch("8");
        id_pkix_ocsp_extended_revoke = aSN1ObjectIdentifier.branch("9");
    }
}