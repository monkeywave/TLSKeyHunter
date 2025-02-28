package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/* loaded from: classes2.dex */
public class TwoDLocation extends ASN1Object {
    private final Latitude latitude;
    private final Longitude longitude;

    /* loaded from: classes2.dex */
    public static class Builder {
        private Latitude latitude;
        private Longitude longitude;

        public TwoDLocation createTwoDLocation() {
            return new TwoDLocation(this.latitude, this.longitude);
        }

        public Builder setLatitude(Latitude latitude) {
            this.latitude = latitude;
            return this;
        }

        public Builder setLongitude(Longitude longitude) {
            this.longitude = longitude;
            return this;
        }
    }

    private TwoDLocation(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 2) {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        this.latitude = Latitude.getInstance((Object) aSN1Sequence.getObjectAt(0));
        this.longitude = Longitude.getInstance((Object) aSN1Sequence.getObjectAt(1));
    }

    public TwoDLocation(Latitude latitude, Longitude longitude) {
        this.latitude = latitude;
        this.longitude = longitude;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static TwoDLocation getInstance(Object obj) {
        if (obj instanceof TwoDLocation) {
            return (TwoDLocation) obj;
        }
        if (obj != null) {
            return new TwoDLocation(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public Latitude getLatitude() {
        return this.latitude;
    }

    public Longitude getLongitude() {
        return this.longitude;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{this.latitude, this.longitude});
    }
}