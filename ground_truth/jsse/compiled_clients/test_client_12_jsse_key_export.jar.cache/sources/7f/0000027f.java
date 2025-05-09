package org.bouncycastle.asn1.misc;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.DERIA5String;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/misc/VerisignCzagExtension.class */
public class VerisignCzagExtension extends DERIA5String {
    public VerisignCzagExtension(ASN1IA5String aSN1IA5String) {
        super(aSN1IA5String.getString());
    }

    @Override // org.bouncycastle.asn1.ASN1IA5String
    public String toString() {
        return "VerisignCzagExtension: " + getString();
    }
}