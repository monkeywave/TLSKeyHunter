package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

/* loaded from: classes.dex */
public interface CRMFObjectIdentifiers {
    public static final ASN1ObjectIdentifier id_alg;
    public static final ASN1ObjectIdentifier id_alg_dh_pop;
    public static final ASN1ObjectIdentifier id_ct_encKeyWithID;
    public static final ASN1ObjectIdentifier id_dh_sig_hmac_sha1;
    public static final ASN1ObjectIdentifier id_pkip;
    public static final ASN1ObjectIdentifier id_pkix;
    public static final ASN1ObjectIdentifier id_regCtrl;
    public static final ASN1ObjectIdentifier id_regCtrl_authenticator;
    public static final ASN1ObjectIdentifier id_regCtrl_oldCertID;
    public static final ASN1ObjectIdentifier id_regCtrl_pkiArchiveOptions;
    public static final ASN1ObjectIdentifier id_regCtrl_pkiPublicationInfo;
    public static final ASN1ObjectIdentifier id_regCtrl_protocolEncrKey;
    public static final ASN1ObjectIdentifier id_regCtrl_regToken;
    public static final ASN1ObjectIdentifier id_regInfo;
    public static final ASN1ObjectIdentifier id_regInfo_certReq;
    public static final ASN1ObjectIdentifier id_regInfo_utf8Pairs;
    public static final ASN1ObjectIdentifier passwordBasedMac = MiscObjectIdentifiers.entrust.branch("66.13");

    static {
        ASN1ObjectIdentifier aSN1ObjectIdentifier = X509ObjectIdentifiers.id_pkix;
        id_pkix = aSN1ObjectIdentifier;
        ASN1ObjectIdentifier branch = aSN1ObjectIdentifier.branch("5");
        id_pkip = branch;
        ASN1ObjectIdentifier branch2 = branch.branch("1");
        id_regCtrl = branch2;
        id_regCtrl_regToken = branch2.branch("1");
        id_regCtrl_authenticator = branch2.branch("2");
        id_regCtrl_pkiPublicationInfo = branch2.branch("3");
        id_regCtrl_pkiArchiveOptions = branch2.branch("4");
        id_regCtrl_oldCertID = branch2.branch("5");
        id_regCtrl_protocolEncrKey = branch2.branch("6");
        ASN1ObjectIdentifier branch3 = branch.branch("2");
        id_regInfo = branch3;
        id_regInfo_utf8Pairs = branch3.branch("1");
        id_regInfo_certReq = branch3.branch("2");
        id_ct_encKeyWithID = PKCSObjectIdentifiers.id_ct.branch("21");
        ASN1ObjectIdentifier aSN1ObjectIdentifier2 = X509ObjectIdentifiers.pkix_algorithms;
        id_alg = aSN1ObjectIdentifier2;
        id_dh_sig_hmac_sha1 = aSN1ObjectIdentifier2.branch("3");
        id_alg_dh_pop = aSN1ObjectIdentifier2.branch("4");
    }
}