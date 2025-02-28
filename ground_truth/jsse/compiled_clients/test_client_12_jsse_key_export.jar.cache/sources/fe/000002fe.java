package org.bouncycastle.asn1.x500;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/x500/X500NameStyle.class */
public interface X500NameStyle {
    ASN1Encodable stringToValue(ASN1ObjectIdentifier aSN1ObjectIdentifier, String str);

    ASN1ObjectIdentifier attrNameToOID(String str);

    RDN[] fromString(String str);

    boolean areEqual(X500Name x500Name, X500Name x500Name2);

    int calculateHashCode(X500Name x500Name);

    String toString(X500Name x500Name);

    String oidToDisplayName(ASN1ObjectIdentifier aSN1ObjectIdentifier);

    String[] oidToAttrNames(ASN1ObjectIdentifier aSN1ObjectIdentifier);
}