package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Certificate;

/* loaded from: classes2.dex */
public class EaEntry extends ASN1Object {
    private final Url aaAccessPoint;
    private final EtsiTs103097Certificate eaCertificate;
    private final Url itsAccessPoint;

    /* loaded from: classes2.dex */
    public static class Builder {
        private Url aaAccessPoint;
        private EtsiTs103097Certificate eaCertificate;
        private Url itsAccessPoint;

        public EaEntry createEaEntry() {
            return new EaEntry(this.eaCertificate, this.aaAccessPoint, this.itsAccessPoint);
        }

        public Builder setAaAccessPoint(Url url) {
            this.aaAccessPoint = url;
            return this;
        }

        public Builder setEaCertificate(EtsiTs103097Certificate etsiTs103097Certificate) {
            this.eaCertificate = etsiTs103097Certificate;
            return this;
        }

        public Builder setItsAccessPoint(Url url) {
            this.itsAccessPoint = url;
            return this;
        }
    }

    private EaEntry(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 3) {
            throw new IllegalArgumentException("expected sequence size of 3");
        }
        this.eaCertificate = EtsiTs103097Certificate.getInstance((Object) aSN1Sequence.getObjectAt(0));
        this.aaAccessPoint = Url.getInstance(aSN1Sequence.getObjectAt(1));
        this.itsAccessPoint = (Url) OEROptional.getValue(Url.class, aSN1Sequence.getObjectAt(2));
    }

    public EaEntry(EtsiTs103097Certificate etsiTs103097Certificate, Url url, Url url2) {
        this.eaCertificate = etsiTs103097Certificate;
        this.aaAccessPoint = url;
        this.itsAccessPoint = url2;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static EaEntry getInstance(Object obj) {
        if (obj instanceof EaEntry) {
            return (EaEntry) obj;
        }
        if (obj != null) {
            return new EaEntry(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public Url getAaAccessPoint() {
        return this.aaAccessPoint;
    }

    public EtsiTs103097Certificate getEaCertificate() {
        return this.eaCertificate;
    }

    public Url getItsAccessPoint() {
        return this.itsAccessPoint;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{this.eaCertificate, this.aaAccessPoint, OEROptional.getInstance(this.itsAccessPoint)});
    }
}