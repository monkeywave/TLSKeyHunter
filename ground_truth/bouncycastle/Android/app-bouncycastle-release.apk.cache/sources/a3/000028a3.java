package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/* loaded from: classes2.dex */
public class ToBeSignedData extends ASN1Object {
    private final HeaderInfo headerInfo;
    private final SignedDataPayload payload;

    /* loaded from: classes2.dex */
    public static class Builder {
        private HeaderInfo headerInfo;
        private SignedDataPayload payload;

        public ToBeSignedData createToBeSignedData() {
            return new ToBeSignedData(this.payload, this.headerInfo);
        }

        public Builder setHeaderInfo(HeaderInfo headerInfo) {
            this.headerInfo = headerInfo;
            return this;
        }

        public Builder setPayload(SignedDataPayload signedDataPayload) {
            this.payload = signedDataPayload;
            return this;
        }
    }

    private ToBeSignedData(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 2) {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        this.payload = SignedDataPayload.getInstance(aSN1Sequence.getObjectAt(0));
        this.headerInfo = HeaderInfo.getInstance(aSN1Sequence.getObjectAt(1));
    }

    public ToBeSignedData(SignedDataPayload signedDataPayload, HeaderInfo headerInfo) {
        this.payload = signedDataPayload;
        this.headerInfo = headerInfo;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static ToBeSignedData getInstance(Object obj) {
        if (obj instanceof ToBeSignedData) {
            return (ToBeSignedData) obj;
        }
        if (obj != null) {
            return new ToBeSignedData(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public HeaderInfo getHeaderInfo() {
        return this.headerInfo;
    }

    public SignedDataPayload getPayload() {
        return this.payload;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{this.payload, this.headerInfo});
    }
}