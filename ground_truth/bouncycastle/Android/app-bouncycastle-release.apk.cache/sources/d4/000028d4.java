package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.BigIntegers;

/* loaded from: classes2.dex */
public class Point256 extends ASN1Object {

    /* renamed from: x */
    private final ASN1OctetString f1166x;

    /* renamed from: y */
    private final ASN1OctetString f1167y;

    /* loaded from: classes2.dex */
    public static class Builder {

        /* renamed from: x */
        private ASN1OctetString f1168x;

        /* renamed from: y */
        private ASN1OctetString f1169y;

        public Point256 createPoint256() {
            return new Point256(this.f1168x, this.f1169y);
        }

        public Builder setX(BigInteger bigInteger) {
            return setX(BigIntegers.asUnsignedByteArray(32, bigInteger));
        }

        public Builder setX(ASN1OctetString aSN1OctetString) {
            this.f1168x = aSN1OctetString;
            return this;
        }

        public Builder setX(byte[] bArr) {
            this.f1168x = new DEROctetString(bArr);
            return this;
        }

        public Builder setY(BigInteger bigInteger) {
            return setY(BigIntegers.asUnsignedByteArray(32, bigInteger));
        }

        public Builder setY(ASN1OctetString aSN1OctetString) {
            this.f1169y = aSN1OctetString;
            return this;
        }

        public Builder setY(byte[] bArr) {
            this.f1169y = new DEROctetString(bArr);
            return this;
        }
    }

    public Point256(ASN1OctetString aSN1OctetString, ASN1OctetString aSN1OctetString2) {
        if (aSN1OctetString == null || aSN1OctetString.getOctets().length != 32) {
            throw new IllegalArgumentException("x must be 32 bytes long");
        }
        if (aSN1OctetString2 == null || aSN1OctetString2.getOctets().length != 32) {
            throw new IllegalArgumentException("y must be 32 bytes long");
        }
        this.f1166x = aSN1OctetString;
        this.f1167y = aSN1OctetString2;
    }

    private Point256(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 2) {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        ASN1OctetString aSN1OctetString = ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(0));
        this.f1166x = aSN1OctetString;
        ASN1OctetString aSN1OctetString2 = ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(1));
        this.f1167y = aSN1OctetString2;
        if (aSN1OctetString.getOctets().length != 32) {
            throw new IllegalArgumentException("x must be 32 bytes long");
        }
        if (aSN1OctetString2.getOctets().length != 32) {
            throw new IllegalArgumentException("y must be 32 bytes long");
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Point256 getInstance(Object obj) {
        if (obj instanceof Point256) {
            return (Point256) obj;
        }
        if (obj != null) {
            return new Point256(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public ASN1OctetString getX() {
        return this.f1166x;
    }

    public ASN1OctetString getY() {
        return this.f1167y;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{this.f1166x, this.f1167y});
    }
}