package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSigned;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

/* loaded from: classes2.dex */
public class CaCertificateRequestMessage extends EtsiTs103097DataSigned {
    protected CaCertificateRequestMessage(ASN1Sequence aSN1Sequence) {
        super(aSN1Sequence);
    }

    public CaCertificateRequestMessage(Ieee1609Dot2Content ieee1609Dot2Content) {
        super(ieee1609Dot2Content);
    }

    public static CaCertificateRequestMessage getInstance(Object obj) {
        if (obj instanceof CaCertificateRequestMessage) {
            return (CaCertificateRequestMessage) obj;
        }
        if (obj != null) {
            return new CaCertificateRequestMessage(ASN1Sequence.getInstance(obj));
        }
        return null;
    }
}