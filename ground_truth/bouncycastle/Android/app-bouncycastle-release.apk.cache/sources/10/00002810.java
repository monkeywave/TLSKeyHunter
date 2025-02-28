package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataEncryptedUnicast;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

/* loaded from: classes2.dex */
public class AuthorizationRequestMessage extends EtsiTs103097DataEncryptedUnicast {
    protected AuthorizationRequestMessage(ASN1Sequence aSN1Sequence) {
        super(aSN1Sequence);
    }

    public AuthorizationRequestMessage(Ieee1609Dot2Content ieee1609Dot2Content) {
        super(ieee1609Dot2Content);
    }

    public static AuthorizationRequestMessage getInstance(Object obj) {
        if (obj instanceof AuthorizationRequestMessage) {
            return (AuthorizationRequestMessage) obj;
        }
        if (obj != null) {
            return new AuthorizationRequestMessage(ASN1Sequence.getInstance(obj));
        }
        return null;
    }
}