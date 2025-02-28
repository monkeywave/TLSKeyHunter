package org.bouncycastle.oer.its.etsi103097;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.ExplicitCertificate;
import org.bouncycastle.oer.its.ieee1609dot2.IssuerIdentifier;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

/* loaded from: classes2.dex */
public class EtsiTs103097Certificate extends ExplicitCertificate {
    protected EtsiTs103097Certificate(ASN1Sequence aSN1Sequence) {
        super(aSN1Sequence);
    }

    public EtsiTs103097Certificate(UINT8 uint8, IssuerIdentifier issuerIdentifier, ToBeSignedCertificate toBeSignedCertificate, Signature signature) {
        super(uint8, issuerIdentifier, toBeSignedCertificate, signature);
    }

    public static EtsiTs103097Certificate getInstance(Object obj) {
        if (obj instanceof EtsiTs103097Certificate) {
            return (EtsiTs103097Certificate) obj;
        }
        if (obj != null) {
            return new EtsiTs103097Certificate(ASN1Sequence.getInstance(obj));
        }
        return null;
    }
}