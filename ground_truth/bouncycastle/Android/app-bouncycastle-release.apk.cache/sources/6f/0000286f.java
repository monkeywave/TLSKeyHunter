package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Certificate;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

/* loaded from: classes2.dex */
public class CertificateBase extends ASN1Object {
    private final IssuerIdentifier issuer;
    private final Signature signature;
    private final ToBeSignedCertificate toBeSigned;
    private final CertificateType type;
    private final UINT8 version;

    /* loaded from: classes2.dex */
    public static class Builder {
        private IssuerIdentifier issuer;
        private Signature signature;
        private ToBeSignedCertificate toBeSigned;
        private CertificateType type;
        private UINT8 version;

        public Certificate createCertificate() {
            return new Certificate(this.version, this.type, this.issuer, this.toBeSigned, this.signature);
        }

        public CertificateBase createCertificateBase() {
            return new CertificateBase(this.version, this.type, this.issuer, this.toBeSigned, this.signature);
        }

        public CertificateBase createEtsiTs103097Certificate() {
            return new EtsiTs103097Certificate(this.version, this.issuer, this.toBeSigned, this.signature);
        }

        public ExplicitCertificate createExplicitCertificate() {
            return new ExplicitCertificate(this.version, this.issuer, this.toBeSigned, this.signature);
        }

        public ImplicitCertificate createImplicitCertificate() {
            return new ImplicitCertificate(this.version, this.issuer, this.toBeSigned, this.signature);
        }

        public Builder setIssuer(IssuerIdentifier issuerIdentifier) {
            this.issuer = issuerIdentifier;
            return this;
        }

        public Builder setSignature(Signature signature) {
            this.signature = signature;
            return this;
        }

        public Builder setToBeSigned(ToBeSignedCertificate toBeSignedCertificate) {
            this.toBeSigned = toBeSignedCertificate;
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

    /* JADX INFO: Access modifiers changed from: protected */
    public CertificateBase(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 5) {
            throw new IllegalArgumentException("expected sequence size of 5");
        }
        this.version = UINT8.getInstance(aSN1Sequence.getObjectAt(0));
        this.type = CertificateType.getInstance((Object) aSN1Sequence.getObjectAt(1));
        this.issuer = IssuerIdentifier.getInstance(aSN1Sequence.getObjectAt(2));
        this.toBeSigned = ToBeSignedCertificate.getInstance(aSN1Sequence.getObjectAt(3));
        this.signature = (Signature) OEROptional.getValue(Signature.class, aSN1Sequence.getObjectAt(4));
    }

    public CertificateBase(UINT8 uint8, CertificateType certificateType, IssuerIdentifier issuerIdentifier, ToBeSignedCertificate toBeSignedCertificate, Signature signature) {
        this.version = uint8;
        this.type = certificateType;
        this.issuer = issuerIdentifier;
        this.toBeSigned = toBeSignedCertificate;
        this.signature = signature;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static CertificateBase getInstance(Object obj) {
        if (obj instanceof CertificateBase) {
            return (CertificateBase) obj;
        }
        if (obj != null) {
            return new CertificateBase(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public IssuerIdentifier getIssuer() {
        return this.issuer;
    }

    public Signature getSignature() {
        return this.signature;
    }

    public ToBeSignedCertificate getToBeSigned() {
        return this.toBeSigned;
    }

    public CertificateType getType() {
        return this.type;
    }

    public UINT8 getVersion() {
        return this.version;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return ItsUtils.toSequence(this.version, this.type, this.issuer, this.toBeSigned, OEROptional.getInstance(this.signature));
    }
}