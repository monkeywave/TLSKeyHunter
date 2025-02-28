package org.bouncycastle.oer.its.ieee1609dot2dot1;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateType;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Time32;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

/* loaded from: classes2.dex */
public class EeEcaCertRequest extends ASN1Object {
    private final ASN1IA5String canonicalId;
    private final Time32 generationTime;
    private final ToBeSignedCertificate tbsCert;
    private final CertificateType type;
    private final UINT8 version;

    /* loaded from: classes2.dex */
    public static class Builder {
        private DERIA5String canonicalId;
        private Time32 generationTime;
        private ToBeSignedCertificate tbsCert;
        private CertificateType type;
        private UINT8 version;

        public EeEcaCertRequest createEeEcaCertRequest() {
            return new EeEcaCertRequest(this.version, this.generationTime, this.type, this.tbsCert, this.canonicalId);
        }

        public Builder setCanonicalId(String str) {
            this.canonicalId = new DERIA5String(str);
            return this;
        }

        public Builder setCanonicalId(DERIA5String dERIA5String) {
            this.canonicalId = dERIA5String;
            return this;
        }

        public Builder setGenerationTime(Time32 time32) {
            this.generationTime = time32;
            return this;
        }

        public Builder setTbsCert(ToBeSignedCertificate toBeSignedCertificate) {
            this.tbsCert = toBeSignedCertificate;
            return this;
        }

        public Builder setType(CertificateType certificateType) {
            this.type = certificateType;
            return this;
        }

        public Builder setVersion(UINT8 uint8) {
            this.version = uint8;
            return this;
        }
    }

    private EeEcaCertRequest(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 5) {
            throw new IllegalArgumentException("expected sequence size of 5");
        }
        this.version = UINT8.getInstance(aSN1Sequence.getObjectAt(0));
        this.generationTime = Time32.getInstance((Object) aSN1Sequence.getObjectAt(1));
        this.type = CertificateType.getInstance((Object) aSN1Sequence.getObjectAt(2));
        this.tbsCert = ToBeSignedCertificate.getInstance(aSN1Sequence.getObjectAt(3));
        this.canonicalId = (ASN1IA5String) OEROptional.getInstance(aSN1Sequence.getObjectAt(4)).getObject(ASN1IA5String.class);
    }

    public EeEcaCertRequest(UINT8 uint8, Time32 time32, CertificateType certificateType, ToBeSignedCertificate toBeSignedCertificate, ASN1IA5String aSN1IA5String) {
        this.version = uint8;
        this.generationTime = time32;
        this.type = certificateType;
        this.tbsCert = toBeSignedCertificate;
        this.canonicalId = aSN1IA5String;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static EeEcaCertRequest getInstance(Object obj) {
        if (obj instanceof EeEcaCertRequest) {
            return (EeEcaCertRequest) obj;
        }
        if (obj != null) {
            return new EeEcaCertRequest(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public ASN1IA5String getCanonicalId() {
        return this.canonicalId;
    }

    public Time32 getGenerationTime() {
        return this.generationTime;
    }

    public ToBeSignedCertificate getTbsCert() {
        return this.tbsCert;
    }

    public CertificateType getType() {
        return this.type;
    }

    public UINT8 getVersion() {
        return this.version;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return ItsUtils.toSequence(this.version, this.generationTime, this.type, this.tbsCert, OEROptional.getInstance(this.canonicalId));
    }
}