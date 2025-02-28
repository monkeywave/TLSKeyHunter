package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSignedAndEncryptedUnicast;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

/* loaded from: classes2.dex */
public class EnrolmentResponseMessage extends EtsiTs103097DataSignedAndEncryptedUnicast {
    protected EnrolmentResponseMessage(ASN1Sequence aSN1Sequence) {
        super(aSN1Sequence);
    }

    public EnrolmentResponseMessage(Ieee1609Dot2Content ieee1609Dot2Content) {
        super(ieee1609Dot2Content);
    }

    public static EnrolmentResponseMessage getInstance(Object obj) {
        if (obj instanceof EnrolmentResponseMessage) {
            return (EnrolmentResponseMessage) obj;
        }
        if (obj != null) {
            return new EnrolmentResponseMessage(ASN1Sequence.getInstance(obj));
        }
        return null;
    }
}