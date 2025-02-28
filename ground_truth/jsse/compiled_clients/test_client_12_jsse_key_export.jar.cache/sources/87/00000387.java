package org.bouncycastle.asn1.p003x9;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.asn1.x9.X9ECPoint */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/x9/X9ECPoint.class */
public class X9ECPoint extends ASN1Object {
    private final ASN1OctetString encoding;

    /* renamed from: c */
    private ECCurve f88c;

    /* renamed from: p */
    private ECPoint f89p;

    public X9ECPoint(ECPoint eCPoint, boolean z) {
        this.f89p = eCPoint.normalize();
        this.encoding = new DEROctetString(eCPoint.getEncoded(z));
    }

    public X9ECPoint(ECCurve eCCurve, byte[] bArr) {
        this.f88c = eCCurve;
        this.encoding = new DEROctetString(Arrays.clone(bArr));
    }

    public X9ECPoint(ECCurve eCCurve, ASN1OctetString aSN1OctetString) {
        this(eCCurve, aSN1OctetString.getOctets());
    }

    public byte[] getPointEncoding() {
        return Arrays.clone(this.encoding.getOctets());
    }

    public synchronized ECPoint getPoint() {
        if (this.f89p == null) {
            this.f89p = this.f88c.decodePoint(this.encoding.getOctets()).normalize();
        }
        return this.f89p;
    }

    public boolean isPointCompressed() {
        byte[] octets = this.encoding.getOctets();
        return octets != null && octets.length > 0 && (octets[0] == 2 || octets[0] == 3);
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.encoding;
    }
}