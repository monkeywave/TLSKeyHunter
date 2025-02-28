package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Certificate;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class InnerEcResponse extends ASN1Object {
    private final EtsiTs103097Certificate certificate;
    private final ASN1OctetString requestHash;
    private final EnrolmentResponseCode responseCode;

    /* loaded from: classes2.dex */
    public static class Builder {
        private EtsiTs103097Certificate certificate;
        private ASN1OctetString requestHash;
        private EnrolmentResponseCode responseCode;

        public InnerEcResponse createInnerEcResponse() {
            return new InnerEcResponse(this.requestHash, this.responseCode, this.certificate);
        }

        public Builder setCertificate(EtsiTs103097Certificate etsiTs103097Certificate) {
            this.certificate = etsiTs103097Certificate;
            return this;
        }

        public Builder setRequestHash(ASN1OctetString aSN1OctetString) {
            this.requestHash = aSN1OctetString;
            return this;
        }

        public Builder setRequestHash(byte[] bArr) {
            this.requestHash = new DEROctetString(Arrays.clone(bArr));
            return this;
        }

        public Builder setResponseCode(EnrolmentResponseCode enrolmentResponseCode) {
            this.responseCode = enrolmentResponseCode;
            return this;
        }
    }

    public InnerEcResponse(ASN1OctetString aSN1OctetString, EnrolmentResponseCode enrolmentResponseCode, EtsiTs103097Certificate etsiTs103097Certificate) {
        this.requestHash = aSN1OctetString;
        this.responseCode = enrolmentResponseCode;
        this.certificate = etsiTs103097Certificate;
    }

    private InnerEcResponse(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 3) {
            throw new IllegalArgumentException("expected sequence size of 3");
        }
        this.requestHash = ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(0));
        this.responseCode = EnrolmentResponseCode.getInstance((Object) aSN1Sequence.getObjectAt(1));
        this.certificate = (EtsiTs103097Certificate) OEROptional.getValue(EtsiTs103097Certificate.class, aSN1Sequence.getObjectAt(2));
    }

    public static Builder builder() {
        return new Builder();
    }

    public static InnerEcResponse getInstance(Object obj) {
        if (obj instanceof InnerEcResponse) {
            return (InnerEcResponse) obj;
        }
        if (obj != null) {
            return new InnerEcResponse(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public EtsiTs103097Certificate getCertificate() {
        return this.certificate;
    }

    public ASN1OctetString getRequestHash() {
        return this.requestHash;
    }

    public EnrolmentResponseCode getResponseCode() {
        return this.responseCode;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{this.requestHash, this.responseCode, OEROptional.getInstance(this.certificate)});
    }
}