package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class EciesP256EncryptedKey extends ASN1Object {

    /* renamed from: c */
    private final ASN1OctetString f1159c;

    /* renamed from: t */
    private final ASN1OctetString f1160t;

    /* renamed from: v */
    private final EccP256CurvePoint f1161v;

    /* loaded from: classes2.dex */
    public static class Builder {

        /* renamed from: c */
        private ASN1OctetString f1162c;

        /* renamed from: t */
        private ASN1OctetString f1163t;

        /* renamed from: v */
        private EccP256CurvePoint f1164v;

        public EciesP256EncryptedKey createEciesP256EncryptedKey() {
            return new EciesP256EncryptedKey(this.f1164v, this.f1162c, this.f1163t);
        }

        public Builder setC(ASN1OctetString aSN1OctetString) {
            this.f1162c = aSN1OctetString;
            return this;
        }

        public Builder setC(byte[] bArr) {
            this.f1162c = new DEROctetString(Arrays.clone(bArr));
            return this;
        }

        public Builder setT(ASN1OctetString aSN1OctetString) {
            this.f1163t = aSN1OctetString;
            return this;
        }

        public Builder setT(byte[] bArr) {
            this.f1163t = new DEROctetString(Arrays.clone(bArr));
            return this;
        }

        public Builder setV(EccP256CurvePoint eccP256CurvePoint) {
            this.f1164v = eccP256CurvePoint;
            return this;
        }
    }

    private EciesP256EncryptedKey(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 3) {
            throw new IllegalArgumentException("expected sequence size of 3");
        }
        this.f1161v = EccP256CurvePoint.getInstance(aSN1Sequence.getObjectAt(0));
        this.f1159c = ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(1));
        this.f1160t = ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(2));
    }

    public EciesP256EncryptedKey(EccP256CurvePoint eccP256CurvePoint, ASN1OctetString aSN1OctetString, ASN1OctetString aSN1OctetString2) {
        this.f1161v = eccP256CurvePoint;
        this.f1159c = aSN1OctetString;
        this.f1160t = aSN1OctetString2;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static EciesP256EncryptedKey getInstance(Object obj) {
        if (obj instanceof EciesP256EncryptedKey) {
            return (EciesP256EncryptedKey) obj;
        }
        if (obj != null) {
            return new EciesP256EncryptedKey(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public ASN1OctetString getC() {
        return this.f1159c;
    }

    public ASN1OctetString getT() {
        return this.f1160t;
    }

    public EccP256CurvePoint getV() {
        return this.f1161v;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{this.f1161v, this.f1159c, this.f1160t});
    }
}