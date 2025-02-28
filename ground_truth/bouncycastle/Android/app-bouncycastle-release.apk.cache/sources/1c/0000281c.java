package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.its.etsi102941.basetypes.CertificateSubjectAttributes;
import org.bouncycastle.oer.its.etsi102941.basetypes.PublicKeys;

/* loaded from: classes2.dex */
public class CaCertificateRequest extends ASN1Object {
    private final PublicKeys publicKeys;
    private final CertificateSubjectAttributes requestedSubjectAttributes;

    /* loaded from: classes2.dex */
    public static class Builder {
        private PublicKeys publicKeys;
        private CertificateSubjectAttributes requestedSubjectAttributes;

        public CaCertificateRequest createCaCertificateRequest() {
            return new CaCertificateRequest(this.publicKeys, this.requestedSubjectAttributes);
        }

        public Builder setPublicKeys(PublicKeys publicKeys) {
            this.publicKeys = publicKeys;
            return this;
        }

        public Builder setRequestedSubjectAttributes(CertificateSubjectAttributes certificateSubjectAttributes) {
            this.requestedSubjectAttributes = certificateSubjectAttributes;
            return this;
        }
    }

    private CaCertificateRequest(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 2) {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        this.publicKeys = PublicKeys.getInstance(aSN1Sequence.getObjectAt(0));
        this.requestedSubjectAttributes = CertificateSubjectAttributes.getInstance(aSN1Sequence.getObjectAt(1));
    }

    public CaCertificateRequest(PublicKeys publicKeys, CertificateSubjectAttributes certificateSubjectAttributes) {
        this.publicKeys = publicKeys;
        this.requestedSubjectAttributes = certificateSubjectAttributes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static CaCertificateRequest getInstance(Object obj) {
        if (obj instanceof CaCertificateRequest) {
            return (CaCertificateRequest) obj;
        }
        if (obj != null) {
            return new CaCertificateRequest(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public PublicKeys getPublicKeys() {
        return this.publicKeys;
    }

    public CertificateSubjectAttributes getRequestedSubjectAttributes() {
        return this.requestedSubjectAttributes;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{this.publicKeys, this.requestedSubjectAttributes});
    }
}