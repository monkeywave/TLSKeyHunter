package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Certificate;

/* loaded from: classes2.dex */
public class AaEntry extends ASN1Object {
    private final EtsiTs103097Certificate aaCertificate;
    private final Url accessPoint;

    /* loaded from: classes2.dex */
    public static class Builder {
        private EtsiTs103097Certificate aaCertificate;
        private Url accessPoint;

        public AaEntry createAaEntry() {
            return new AaEntry(this.aaCertificate, this.accessPoint);
        }

        public Builder setAaCertificate(EtsiTs103097Certificate etsiTs103097Certificate) {
            this.aaCertificate = etsiTs103097Certificate;
            return this;
        }

        public Builder setAccessPoint(Url url) {
            this.accessPoint = url;
            return this;
        }
    }

    private AaEntry(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 2) {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        this.aaCertificate = EtsiTs103097Certificate.getInstance((Object) aSN1Sequence.getObjectAt(0));
        this.accessPoint = Url.getInstance(aSN1Sequence.getObjectAt(1));
    }

    public AaEntry(EtsiTs103097Certificate etsiTs103097Certificate, Url url) {
        this.aaCertificate = etsiTs103097Certificate;
        this.accessPoint = url;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static AaEntry getInstance(Object obj) {
        if (obj instanceof AaEntry) {
            return (AaEntry) obj;
        }
        if (obj != null) {
            return new AaEntry(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public EtsiTs103097Certificate getAaCertificate() {
        return this.aaCertificate;
    }

    public Url getAccessPoint() {
        return this.accessPoint;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{this.aaCertificate, this.accessPoint});
    }
}