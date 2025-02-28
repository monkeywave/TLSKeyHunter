package org.bouncycastle.oer.its.ieee1609dot2;

import java.util.Iterator;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.CrlSeries;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.GeographicRegion;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId3;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicEncryptionKey;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfPsidSsp;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SubjectAssurance;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.ValidityPeriod;

/* loaded from: classes2.dex */
public class ToBeSignedCertificate extends ASN1Object {
    private final SequenceOfPsidSsp appPermissions;
    private final SubjectAssurance assuranceLevel;
    private final ASN1Null canRequestRollover;
    private final SequenceOfPsidGroupPermissions certIssuePermissions;
    private final SequenceOfPsidGroupPermissions certRequestPermissions;
    private final HashedId3 cracaId;
    private final CrlSeries crlSeries;
    private final PublicEncryptionKey encryptionKey;

    /* renamed from: id */
    private final CertificateId f1157id;
    private final GeographicRegion region;
    private final ValidityPeriod validityPeriod;
    private final VerificationKeyIndicator verifyKeyIndicator;

    /* loaded from: classes2.dex */
    public static class Builder {
        private SequenceOfPsidSsp appPermissions;
        private SubjectAssurance assuranceLevel;
        private ASN1Null canRequestRollover;
        private SequenceOfPsidGroupPermissions certIssuePermissions;
        private SequenceOfPsidGroupPermissions certRequestPermissions;
        private HashedId3 cracaId;
        private CrlSeries crlSeries;
        private PublicEncryptionKey encryptionKey;

        /* renamed from: id */
        private CertificateId f1158id;
        private GeographicRegion region;
        private ValidityPeriod validityPeriod;
        private VerificationKeyIndicator verifyKeyIndicator;

        public Builder() {
        }

        public Builder(Builder builder) {
            this.f1158id = builder.f1158id;
            this.cracaId = builder.cracaId;
            this.crlSeries = builder.crlSeries;
            this.validityPeriod = builder.validityPeriod;
            this.region = builder.region;
            this.assuranceLevel = builder.assuranceLevel;
            this.appPermissions = builder.appPermissions;
            this.certIssuePermissions = builder.certIssuePermissions;
            this.certRequestPermissions = builder.certRequestPermissions;
            this.canRequestRollover = builder.canRequestRollover;
            this.encryptionKey = builder.encryptionKey;
            this.verifyKeyIndicator = builder.verifyKeyIndicator;
        }

        public Builder(ToBeSignedCertificate toBeSignedCertificate) {
            this.f1158id = toBeSignedCertificate.f1157id;
            this.cracaId = toBeSignedCertificate.cracaId;
            this.crlSeries = toBeSignedCertificate.crlSeries;
            this.validityPeriod = toBeSignedCertificate.validityPeriod;
            this.region = toBeSignedCertificate.region;
            this.assuranceLevel = toBeSignedCertificate.assuranceLevel;
            this.appPermissions = toBeSignedCertificate.appPermissions;
            this.certIssuePermissions = toBeSignedCertificate.certIssuePermissions;
            this.certRequestPermissions = toBeSignedCertificate.certRequestPermissions;
            this.canRequestRollover = toBeSignedCertificate.canRequestRollover;
            this.encryptionKey = toBeSignedCertificate.encryptionKey;
            this.verifyKeyIndicator = toBeSignedCertificate.verifyKeyIndicator;
        }

        public ToBeSignedCertificate createToBeSignedCertificate() {
            return new ToBeSignedCertificate(this.f1158id, this.cracaId, this.crlSeries, this.validityPeriod, this.region, this.assuranceLevel, this.appPermissions, this.certIssuePermissions, this.certRequestPermissions, this.canRequestRollover, this.encryptionKey, this.verifyKeyIndicator);
        }

        public Builder setAppPermissions(SequenceOfPsidSsp sequenceOfPsidSsp) {
            this.appPermissions = sequenceOfPsidSsp;
            return this;
        }

        public Builder setAssuranceLevel(SubjectAssurance subjectAssurance) {
            this.assuranceLevel = subjectAssurance;
            return this;
        }

        public Builder setCanRequestRollover() {
            this.canRequestRollover = DERNull.INSTANCE;
            return this;
        }

        public Builder setCertIssuePermissions(SequenceOfPsidGroupPermissions sequenceOfPsidGroupPermissions) {
            this.certIssuePermissions = sequenceOfPsidGroupPermissions;
            return this;
        }

        public Builder setCertRequestPermissions(SequenceOfPsidGroupPermissions sequenceOfPsidGroupPermissions) {
            this.certRequestPermissions = sequenceOfPsidGroupPermissions;
            return this;
        }

        public Builder setCracaId(HashedId3 hashedId3) {
            this.cracaId = hashedId3;
            return this;
        }

        public Builder setCrlSeries(CrlSeries crlSeries) {
            this.crlSeries = crlSeries;
            return this;
        }

        public Builder setEncryptionKey(PublicEncryptionKey publicEncryptionKey) {
            this.encryptionKey = publicEncryptionKey;
            return this;
        }

        public Builder setId(CertificateId certificateId) {
            this.f1158id = certificateId;
            return this;
        }

        public Builder setRegion(GeographicRegion geographicRegion) {
            this.region = geographicRegion;
            return this;
        }

        public Builder setValidityPeriod(ValidityPeriod validityPeriod) {
            this.validityPeriod = validityPeriod;
            return this;
        }

        public Builder setVerifyKeyIndicator(VerificationKeyIndicator verificationKeyIndicator) {
            this.verifyKeyIndicator = verificationKeyIndicator;
            return this;
        }
    }

    private ToBeSignedCertificate(ASN1Sequence aSN1Sequence) {
        Iterator<ASN1Encodable> it = ASN1Sequence.getInstance(aSN1Sequence).iterator();
        if (aSN1Sequence.size() != 12) {
            throw new IllegalArgumentException("expected sequence size of 12");
        }
        this.f1157id = CertificateId.getInstance(it.next());
        this.cracaId = HashedId3.getInstance(it.next());
        this.crlSeries = CrlSeries.getInstance((Object) it.next());
        this.validityPeriod = ValidityPeriod.getInstance(it.next());
        this.region = (GeographicRegion) OEROptional.getValue(GeographicRegion.class, it.next());
        this.assuranceLevel = (SubjectAssurance) OEROptional.getValue(SubjectAssurance.class, it.next());
        this.appPermissions = (SequenceOfPsidSsp) OEROptional.getValue(SequenceOfPsidSsp.class, it.next());
        this.certIssuePermissions = (SequenceOfPsidGroupPermissions) OEROptional.getValue(SequenceOfPsidGroupPermissions.class, it.next());
        this.certRequestPermissions = (SequenceOfPsidGroupPermissions) OEROptional.getValue(SequenceOfPsidGroupPermissions.class, it.next());
        this.canRequestRollover = (ASN1Null) OEROptional.getValue(ASN1Null.class, it.next());
        this.encryptionKey = (PublicEncryptionKey) OEROptional.getValue(PublicEncryptionKey.class, it.next());
        this.verifyKeyIndicator = VerificationKeyIndicator.getInstance(it.next());
    }

    public ToBeSignedCertificate(CertificateId certificateId, HashedId3 hashedId3, CrlSeries crlSeries, ValidityPeriod validityPeriod, GeographicRegion geographicRegion, SubjectAssurance subjectAssurance, SequenceOfPsidSsp sequenceOfPsidSsp, SequenceOfPsidGroupPermissions sequenceOfPsidGroupPermissions, SequenceOfPsidGroupPermissions sequenceOfPsidGroupPermissions2, ASN1Null aSN1Null, PublicEncryptionKey publicEncryptionKey, VerificationKeyIndicator verificationKeyIndicator) {
        this.f1157id = certificateId;
        this.cracaId = hashedId3;
        this.crlSeries = crlSeries;
        this.validityPeriod = validityPeriod;
        this.region = geographicRegion;
        this.assuranceLevel = subjectAssurance;
        this.appPermissions = sequenceOfPsidSsp;
        this.certIssuePermissions = sequenceOfPsidGroupPermissions;
        this.certRequestPermissions = sequenceOfPsidGroupPermissions2;
        this.canRequestRollover = aSN1Null;
        this.encryptionKey = publicEncryptionKey;
        this.verifyKeyIndicator = verificationKeyIndicator;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static ToBeSignedCertificate getInstance(Object obj) {
        if (obj instanceof ToBeSignedCertificate) {
            return (ToBeSignedCertificate) obj;
        }
        if (obj != null) {
            return new ToBeSignedCertificate(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public SequenceOfPsidSsp getAppPermissions() {
        return this.appPermissions;
    }

    public SubjectAssurance getAssuranceLevel() {
        return this.assuranceLevel;
    }

    public ASN1Null getCanRequestRollover() {
        return this.canRequestRollover;
    }

    public SequenceOfPsidGroupPermissions getCertIssuePermissions() {
        return this.certIssuePermissions;
    }

    public SequenceOfPsidGroupPermissions getCertRequestPermissions() {
        return this.certRequestPermissions;
    }

    public HashedId3 getCracaId() {
        return this.cracaId;
    }

    public CrlSeries getCrlSeries() {
        return this.crlSeries;
    }

    public PublicEncryptionKey getEncryptionKey() {
        return this.encryptionKey;
    }

    public CertificateId getId() {
        return this.f1157id;
    }

    public GeographicRegion getRegion() {
        return this.region;
    }

    public ValidityPeriod getValidityPeriod() {
        return this.validityPeriod;
    }

    public VerificationKeyIndicator getVerifyKeyIndicator() {
        return this.verifyKeyIndicator;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return ItsUtils.toSequence(this.f1157id, this.cracaId, this.crlSeries, this.validityPeriod, OEROptional.getInstance(this.region), OEROptional.getInstance(this.assuranceLevel), OEROptional.getInstance(this.appPermissions), OEROptional.getInstance(this.certIssuePermissions), OEROptional.getInstance(this.certRequestPermissions), OEROptional.getInstance(this.canRequestRollover), OEROptional.getInstance(this.encryptionKey), this.verifyKeyIndicator);
    }
}