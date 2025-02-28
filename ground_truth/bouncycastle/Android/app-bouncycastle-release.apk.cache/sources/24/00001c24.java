package org.bouncycastle.asn1.p009x9;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.math.p016ec.ECPoint;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.asn1.x9.X9ECPoint */
/* loaded from: classes.dex */
public class X9ECPoint extends ASN1Object {

    /* renamed from: c */
    private ECCurve f332c;
    private final ASN1OctetString encoding;

    /* renamed from: p */
    private ECPoint f333p;

    public X9ECPoint(ECCurve eCCurve, ASN1OctetString aSN1OctetString) {
        this(eCCurve, aSN1OctetString.getOctets());
    }

    public X9ECPoint(ECCurve eCCurve, byte[] bArr) {
        this.f332c = eCCurve;
        this.encoding = new DEROctetString(Arrays.clone(bArr));
    }

    public X9ECPoint(ECPoint eCPoint, boolean z) {
        this.f333p = eCPoint.normalize();
        this.encoding = new DEROctetString(eCPoint.getEncoded(z));
    }

    public synchronized ECPoint getPoint() {
        if (this.f333p == null) {
            this.f333p = this.f332c.decodePoint(this.encoding.getOctets()).normalize();
        }
        return this.f333p;
    }

    public byte[] getPointEncoding() {
        return Arrays.clone(this.encoding.getOctets());
    }

    public boolean isPointCompressed() {
        byte[] octets = this.encoding.getOctets();
        if (octets == null || octets.length <= 0) {
            return false;
        }
        byte b = octets[0];
        return b == 2 || b == 3;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.encoding;
    }
}