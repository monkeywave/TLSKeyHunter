package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.its.ieee1609dot2.HashedData;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Time32;

/* loaded from: classes2.dex */
public class ToBeSignedLinkCertificate extends ASN1Object {
    private final HashedData certificateHash;
    private final Time32 expiryTime;

    /* loaded from: classes2.dex */
    public static class Builder {
        private HashedData certificateHash;
        private Time32 expiryTime;

        public ToBeSignedLinkCertificate createToBeSignedLinkCertificate() {
            return new ToBeSignedLinkCertificate(this.expiryTime, this.certificateHash);
        }

        public ToBeSignedLinkCertificateRca createToBeSignedLinkCertificateRca() {
            return new ToBeSignedLinkCertificateRca(this.expiryTime, this.certificateHash);
        }

        public ToBeSignedLinkCertificateTlm createToBeSignedLinkCertificateTlm() {
            return new ToBeSignedLinkCertificateTlm(this.expiryTime, this.certificateHash);
        }

        public Builder setCertificateHash(HashedData hashedData) {
            this.certificateHash = hashedData;
            return this;
        }

        public Builder setExpiryTime(Time32 time32) {
            this.expiryTime = time32;
            return this;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public ToBeSignedLinkCertificate(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 2) {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        this.expiryTime = Time32.getInstance((Object) aSN1Sequence.getObjectAt(0));
        this.certificateHash = HashedData.getInstance(aSN1Sequence.getObjectAt(1));
    }

    public ToBeSignedLinkCertificate(Time32 time32, HashedData hashedData) {
        this.expiryTime = time32;
        this.certificateHash = hashedData;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static ToBeSignedLinkCertificate getInstance(Object obj) {
        if (obj instanceof ToBeSignedLinkCertificate) {
            return (ToBeSignedLinkCertificate) obj;
        }
        if (obj != null) {
            return new ToBeSignedLinkCertificate(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public HashedData getCertificateHash() {
        return this.certificateHash;
    }

    public Time32 getExpiryTime() {
        return this.expiryTime;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{this.expiryTime, this.certificateHash});
    }
}