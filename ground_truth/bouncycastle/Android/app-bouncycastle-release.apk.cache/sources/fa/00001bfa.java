package org.bouncycastle.asn1.x509.qualified;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

/* loaded from: classes.dex */
public interface RFC3739QCObjectIdentifiers {
    public static final ASN1ObjectIdentifier id_qcs;
    public static final ASN1ObjectIdentifier id_qcs_pkixQCSyntax_v1;
    public static final ASN1ObjectIdentifier id_qcs_pkixQCSyntax_v2;

    static {
        ASN1ObjectIdentifier branch = X509ObjectIdentifiers.id_pkix.branch("11");
        id_qcs = branch;
        id_qcs_pkixQCSyntax_v1 = branch.branch("1");
        id_qcs_pkixQCSyntax_v2 = branch.branch("2");
    }
}