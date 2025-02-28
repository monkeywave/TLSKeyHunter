package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;

/* loaded from: classes2.dex */
public class RegionAndSubregions extends ASN1Object implements RegionInterface {
    private final UINT8 region;
    private final SequenceOfUint16 subregions;

    /* loaded from: classes2.dex */
    public static class Builder {
        private UINT8 region;
        private SequenceOfUint16 subRegions;

        public RegionAndSubregions createRegionAndSubregions() {
            return new RegionAndSubregions(this.region, this.subRegions);
        }

        public Builder setRegion(UINT8 uint8) {
            this.region = uint8;
            return this;
        }

        public Builder setSubregions(SequenceOfUint16 sequenceOfUint16) {
            this.subRegions = sequenceOfUint16;
            return this;
        }
    }

    private RegionAndSubregions(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 2) {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        this.region = UINT8.getInstance(aSN1Sequence.getObjectAt(0));
        this.subregions = SequenceOfUint16.getInstance(aSN1Sequence.getObjectAt(1));
    }

    public RegionAndSubregions(UINT8 uint8, SequenceOfUint16 sequenceOfUint16) {
        this.region = uint8;
        this.subregions = sequenceOfUint16;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static RegionAndSubregions getInstance(Object obj) {
        if (obj instanceof RegionAndSubregions) {
            return (RegionAndSubregions) obj;
        }
        if (obj != null) {
            return new RegionAndSubregions(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public UINT8 getRegion() {
        return this.region;
    }

    public SequenceOfUint16 getSubregions() {
        return this.subregions;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return ItsUtils.toSequence(this.region, this.subregions);
    }
}