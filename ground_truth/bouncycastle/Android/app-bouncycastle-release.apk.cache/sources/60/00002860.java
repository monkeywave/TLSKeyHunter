package org.bouncycastle.oer.its.etsi103097;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

/* loaded from: classes2.dex */
public class EtsiTs103097DataSignedExternalPayload extends EtsiTs103097Data {
    protected EtsiTs103097DataSignedExternalPayload(ASN1Sequence aSN1Sequence) {
        super(aSN1Sequence);
    }

    public EtsiTs103097DataSignedExternalPayload(Ieee1609Dot2Content ieee1609Dot2Content) {
        super(ieee1609Dot2Content);
    }

    public static EtsiTs103097DataSignedExternalPayload getInstance(Object obj) {
        if (obj instanceof EtsiTs103097DataSignedExternalPayload) {
            return (EtsiTs103097DataSignedExternalPayload) obj;
        }
        if (obj != null) {
            return new EtsiTs103097DataSignedExternalPayload(ASN1Sequence.getInstance(obj));
        }
        return null;
    }
}