package org.bouncycastle.oer.its.etsi103097;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

/* loaded from: classes2.dex */
public class EtsiTs103097DataSigned extends EtsiTs103097Data {
    /* JADX INFO: Access modifiers changed from: protected */
    public EtsiTs103097DataSigned(ASN1Sequence aSN1Sequence) {
        super(aSN1Sequence);
    }

    public EtsiTs103097DataSigned(Ieee1609Dot2Content ieee1609Dot2Content) {
        super(ieee1609Dot2Content);
    }

    public static EtsiTs103097DataSigned getInstance(Object obj) {
        if (obj instanceof EtsiTs103097DataSigned) {
            return (EtsiTs103097DataSigned) obj;
        }
        if (obj != null) {
            return new EtsiTs103097DataSigned(ASN1Sequence.getInstance(obj));
        }
        return null;
    }
}