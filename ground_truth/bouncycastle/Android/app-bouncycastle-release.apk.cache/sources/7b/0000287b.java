package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

/* loaded from: classes2.dex */
public class ExplicitCertificate extends CertificateBase {
    /* JADX INFO: Access modifiers changed from: protected */
    public ExplicitCertificate(ASN1Sequence aSN1Sequence) {
        super(aSN1Sequence);
        if (!getType().equals((ASN1Primitive) CertificateType.explicit)) {
            throw new IllegalArgumentException("object was certificate base but the type was not explicit");
        }
    }

    public ExplicitCertificate(CertificateBase certificateBase) {
        this(certificateBase.getVersion(), certificateBase.getIssuer(), certificateBase.getToBeSigned(), certificateBase.getSignature());
    }

    public ExplicitCertificate(UINT8 uint8, IssuerIdentifier issuerIdentifier, ToBeSignedCertificate toBeSignedCertificate, Signature signature) {
        super(uint8, CertificateType.explicit, issuerIdentifier, toBeSignedCertificate, signature);
    }

    public static ExplicitCertificate getInstance(Object obj) {
        if (obj instanceof ExplicitCertificate) {
            return (ExplicitCertificate) obj;
        }
        if (obj != null) {
            return new ExplicitCertificate(ASN1Sequence.getInstance(obj));
        }
        return null;
    }
}