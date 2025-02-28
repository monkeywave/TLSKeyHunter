package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSigned;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

/* loaded from: classes2.dex */
public class CaCertificateRekeyingMessage extends EtsiTs103097DataSigned {
    protected CaCertificateRekeyingMessage(ASN1Sequence aSN1Sequence) {
        super(aSN1Sequence);
    }

    public CaCertificateRekeyingMessage(Ieee1609Dot2Content ieee1609Dot2Content) {
        super(ieee1609Dot2Content);
    }

    public static CaCertificateRekeyingMessage getInstance(Object obj) {
        if (obj instanceof CaCertificateRekeyingMessage) {
            return (CaCertificateRekeyingMessage) obj;
        }
        if (obj != null) {
            return new CaCertificateRekeyingMessage(ASN1Sequence.getInstance(obj));
        }
        return null;
    }
}