package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/x509/PolicyQualifierId.class */
public class PolicyQualifierId extends ASN1ObjectIdentifier {
    private static final String id_qt = "1.3.6.1.5.5.7.2";
    public static final PolicyQualifierId id_qt_cps = new PolicyQualifierId("1.3.6.1.5.5.7.2.1");
    public static final PolicyQualifierId id_qt_unotice = new PolicyQualifierId("1.3.6.1.5.5.7.2.2");

    private PolicyQualifierId(String str) {
        super(str);
    }
}