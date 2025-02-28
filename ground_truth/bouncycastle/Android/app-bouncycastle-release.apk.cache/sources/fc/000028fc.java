package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERTaggedObject;

/* loaded from: classes2.dex */
public class SspRange extends ASN1Object implements ASN1Choice {
    public static final int all = 1;
    public static final int bitmapSspRange = 2;
    public static final int opaque = 0;
    private final int choice;
    private final ASN1Encodable sspRange;

    public SspRange(int i, ASN1Encodable aSN1Encodable) {
        if (i != 0 && i != 1 && i != 2) {
            throw new IllegalArgumentException("invalid choice value " + i);
        }
        this.choice = i;
        this.sspRange = aSN1Encodable;
    }

    private SspRange(ASN1TaggedObject aSN1TaggedObject) {
        this(aSN1TaggedObject.getTagNo(), aSN1TaggedObject.getExplicitBaseObject());
    }

    public static SspRange all() {
        return new SspRange(1, DERNull.INSTANCE);
    }

    public static SspRange bitmapSspRange(BitmapSspRange bitmapSspRange2) {
        return new SspRange(2, bitmapSspRange2);
    }

    public static SspRange getInstance(Object obj) {
        if (obj instanceof SspRange) {
            return (SspRange) obj;
        }
        if (obj != null) {
            return new SspRange(ASN1TaggedObject.getInstance(obj, 128));
        }
        return null;
    }

    public static SspRange opaque(SequenceOfOctetString sequenceOfOctetString) {
        return new SspRange(0, sequenceOfOctetString);
    }

    public int getChoice() {
        return this.choice;
    }

    public ASN1Encodable getSspRange() {
        return this.sspRange;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERTaggedObject(this.choice, this.sspRange);
    }
}