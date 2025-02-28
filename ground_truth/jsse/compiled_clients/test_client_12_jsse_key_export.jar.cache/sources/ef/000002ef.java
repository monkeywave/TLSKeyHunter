package org.bouncycastle.asn1.p002ua;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/* renamed from: org.bouncycastle.asn1.ua.DSTU4145BinaryField */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ua/DSTU4145BinaryField.class */
public class DSTU4145BinaryField extends ASN1Object {

    /* renamed from: m */
    private int f32m;

    /* renamed from: k */
    private int f33k;

    /* renamed from: j */
    private int f34j;

    /* renamed from: l */
    private int f35l;

    private DSTU4145BinaryField(ASN1Sequence aSN1Sequence) {
        this.f32m = ASN1Integer.getInstance(aSN1Sequence.getObjectAt(0)).intPositiveValueExact();
        if (aSN1Sequence.getObjectAt(1) instanceof ASN1Integer) {
            this.f33k = ((ASN1Integer) aSN1Sequence.getObjectAt(1)).intPositiveValueExact();
        } else if (!(aSN1Sequence.getObjectAt(1) instanceof ASN1Sequence)) {
            throw new IllegalArgumentException("object parse error");
        } else {
            ASN1Sequence aSN1Sequence2 = ASN1Sequence.getInstance(aSN1Sequence.getObjectAt(1));
            this.f33k = ASN1Integer.getInstance(aSN1Sequence2.getObjectAt(0)).intPositiveValueExact();
            this.f34j = ASN1Integer.getInstance(aSN1Sequence2.getObjectAt(1)).intPositiveValueExact();
            this.f35l = ASN1Integer.getInstance(aSN1Sequence2.getObjectAt(2)).intPositiveValueExact();
        }
    }

    public static DSTU4145BinaryField getInstance(Object obj) {
        if (obj instanceof DSTU4145BinaryField) {
            return (DSTU4145BinaryField) obj;
        }
        if (obj != null) {
            return new DSTU4145BinaryField(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public DSTU4145BinaryField(int i, int i2, int i3, int i4) {
        this.f32m = i;
        this.f33k = i2;
        this.f34j = i3;
        this.f35l = i4;
    }

    public int getM() {
        return this.f32m;
    }

    public int getK1() {
        return this.f33k;
    }

    public int getK2() {
        return this.f34j;
    }

    public int getK3() {
        return this.f35l;
    }

    public DSTU4145BinaryField(int i, int i2) {
        this(i, i2, 0, 0);
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
        aSN1EncodableVector.add(new ASN1Integer(this.f32m));
        if (this.f34j == 0) {
            aSN1EncodableVector.add(new ASN1Integer(this.f33k));
        } else {
            ASN1EncodableVector aSN1EncodableVector2 = new ASN1EncodableVector(3);
            aSN1EncodableVector2.add(new ASN1Integer(this.f33k));
            aSN1EncodableVector2.add(new ASN1Integer(this.f34j));
            aSN1EncodableVector2.add(new ASN1Integer(this.f35l));
            aSN1EncodableVector.add(new DERSequence(aSN1EncodableVector2));
        }
        return new DERSequence(aSN1EncodableVector);
    }
}