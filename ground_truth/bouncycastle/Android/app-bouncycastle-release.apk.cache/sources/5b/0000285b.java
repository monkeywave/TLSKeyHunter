package org.bouncycastle.oer.its.etsi103097;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

/* loaded from: classes2.dex */
public class EtsiTs103097DataEncrypted extends EtsiTs103097Data {
    protected EtsiTs103097DataEncrypted(ASN1Sequence aSN1Sequence) {
        super(aSN1Sequence);
    }

    public EtsiTs103097DataEncrypted(Ieee1609Dot2Content ieee1609Dot2Content) {
        super(ieee1609Dot2Content);
    }

    public static EtsiTs103097DataEncrypted getInstance(Object obj) {
        if (obj instanceof EtsiTs103097DataEncrypted) {
            return (EtsiTs103097DataEncrypted) obj;
        }
        if (obj != null) {
            return new EtsiTs103097DataEncrypted(ASN1Sequence.getInstance(obj));
        }
        return null;
    }
}