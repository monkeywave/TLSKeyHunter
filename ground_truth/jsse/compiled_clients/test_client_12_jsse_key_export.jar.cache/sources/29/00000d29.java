package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/asn1/ParSet.class */
public class ParSet extends ASN1Object {

    /* renamed from: t */
    private int f806t;

    /* renamed from: h */
    private int[] f807h;

    /* renamed from: w */
    private int[] f808w;

    /* renamed from: k */
    private int[] f809k;

    private static int checkBigIntegerInIntRangeAndPositive(ASN1Encodable aSN1Encodable) {
        int intValueExact = ((ASN1Integer) aSN1Encodable).intValueExact();
        if (intValueExact <= 0) {
            throw new IllegalArgumentException("BigInteger not in Range: " + intValueExact);
        }
        return intValueExact;
    }

    private ParSet(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 4) {
            throw new IllegalArgumentException("sie of seqOfParams = " + aSN1Sequence.size());
        }
        this.f806t = checkBigIntegerInIntRangeAndPositive(aSN1Sequence.getObjectAt(0));
        ASN1Sequence aSN1Sequence2 = (ASN1Sequence) aSN1Sequence.getObjectAt(1);
        ASN1Sequence aSN1Sequence3 = (ASN1Sequence) aSN1Sequence.getObjectAt(2);
        ASN1Sequence aSN1Sequence4 = (ASN1Sequence) aSN1Sequence.getObjectAt(3);
        if (aSN1Sequence2.size() != this.f806t || aSN1Sequence3.size() != this.f806t || aSN1Sequence4.size() != this.f806t) {
            throw new IllegalArgumentException("invalid size of sequences");
        }
        this.f807h = new int[aSN1Sequence2.size()];
        this.f808w = new int[aSN1Sequence3.size()];
        this.f809k = new int[aSN1Sequence4.size()];
        for (int i = 0; i < this.f806t; i++) {
            this.f807h[i] = checkBigIntegerInIntRangeAndPositive(aSN1Sequence2.getObjectAt(i));
            this.f808w[i] = checkBigIntegerInIntRangeAndPositive(aSN1Sequence3.getObjectAt(i));
            this.f809k[i] = checkBigIntegerInIntRangeAndPositive(aSN1Sequence4.getObjectAt(i));
        }
    }

    public ParSet(int i, int[] iArr, int[] iArr2, int[] iArr3) {
        this.f806t = i;
        this.f807h = iArr;
        this.f808w = iArr2;
        this.f809k = iArr3;
    }

    public static ParSet getInstance(Object obj) {
        if (obj instanceof ParSet) {
            return (ParSet) obj;
        }
        if (obj != null) {
            return new ParSet(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public int getT() {
        return this.f806t;
    }

    public int[] getH() {
        return Arrays.clone(this.f807h);
    }

    public int[] getW() {
        return Arrays.clone(this.f808w);
    }

    public int[] getK() {
        return Arrays.clone(this.f809k);
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        ASN1EncodableVector aSN1EncodableVector2 = new ASN1EncodableVector();
        ASN1EncodableVector aSN1EncodableVector3 = new ASN1EncodableVector();
        for (int i = 0; i < this.f807h.length; i++) {
            aSN1EncodableVector.add(new ASN1Integer(this.f807h[i]));
            aSN1EncodableVector2.add(new ASN1Integer(this.f808w[i]));
            aSN1EncodableVector3.add(new ASN1Integer(this.f809k[i]));
        }
        ASN1EncodableVector aSN1EncodableVector4 = new ASN1EncodableVector();
        aSN1EncodableVector4.add(new ASN1Integer(this.f806t));
        aSN1EncodableVector4.add(new DERSequence(aSN1EncodableVector));
        aSN1EncodableVector4.add(new DERSequence(aSN1EncodableVector2));
        aSN1EncodableVector4.add(new DERSequence(aSN1EncodableVector3));
        return new DERSequence(aSN1EncodableVector4);
    }
}