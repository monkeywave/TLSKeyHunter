package org.bouncycastle.asn1.util;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;

/* loaded from: classes.dex */
public class DERDump extends ASN1Dump {
    public static String dumpAsString(ASN1Encodable aSN1Encodable) {
        return dumpAsString(aSN1Encodable.toASN1Primitive());
    }

    public static String dumpAsString(ASN1Primitive aSN1Primitive) {
        StringBuffer stringBuffer = new StringBuffer();
        _dumpAsString("", false, aSN1Primitive, stringBuffer);
        return stringBuffer.toString();
    }
}