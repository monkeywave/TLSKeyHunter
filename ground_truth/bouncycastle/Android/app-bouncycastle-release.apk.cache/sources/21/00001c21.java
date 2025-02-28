package org.bouncycastle.asn1.p009x9;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.math.p016ec.ECAlgorithms;
import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.asn1.x9.X9Curve */
/* loaded from: classes.dex */
public class X9Curve extends ASN1Object implements X9ObjectIdentifiers {
    private ECCurve curve;
    private ASN1ObjectIdentifier fieldIdentifier;
    private byte[] seed;

    public X9Curve(X9FieldID x9FieldID, BigInteger bigInteger, BigInteger bigInteger2, ASN1Sequence aSN1Sequence) {
        int intValueExact;
        int i;
        int i2;
        ECCurve f2m;
        this.fieldIdentifier = null;
        ASN1ObjectIdentifier identifier = x9FieldID.getIdentifier();
        this.fieldIdentifier = identifier;
        if (identifier.equals((ASN1Primitive) prime_field)) {
            f2m = new ECCurve.C1333Fp(((ASN1Integer) x9FieldID.getParameters()).getValue(), new BigInteger(1, ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(0)).getOctets()), new BigInteger(1, ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(1)).getOctets()), bigInteger, bigInteger2);
        } else if (!this.fieldIdentifier.equals((ASN1Primitive) characteristic_two_field)) {
            throw new IllegalArgumentException("This type of ECCurve is not implemented");
        } else {
            ASN1Sequence aSN1Sequence2 = ASN1Sequence.getInstance(x9FieldID.getParameters());
            int intValueExact2 = ((ASN1Integer) aSN1Sequence2.getObjectAt(0)).intValueExact();
            ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) aSN1Sequence2.getObjectAt(1);
            if (aSN1ObjectIdentifier.equals((ASN1Primitive) tpBasis)) {
                i = ASN1Integer.getInstance(aSN1Sequence2.getObjectAt(2)).intValueExact();
                i2 = 0;
                intValueExact = 0;
            } else if (!aSN1ObjectIdentifier.equals((ASN1Primitive) ppBasis)) {
                throw new IllegalArgumentException("This type of EC basis is not implemented");
            } else {
                ASN1Sequence aSN1Sequence3 = ASN1Sequence.getInstance(aSN1Sequence2.getObjectAt(2));
                int intValueExact3 = ASN1Integer.getInstance(aSN1Sequence3.getObjectAt(0)).intValueExact();
                int intValueExact4 = ASN1Integer.getInstance(aSN1Sequence3.getObjectAt(1)).intValueExact();
                intValueExact = ASN1Integer.getInstance(aSN1Sequence3.getObjectAt(2)).intValueExact();
                i = intValueExact3;
                i2 = intValueExact4;
            }
            f2m = new ECCurve.F2m(intValueExact2, i, i2, intValueExact, new BigInteger(1, ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(0)).getOctets()), new BigInteger(1, ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(1)).getOctets()), bigInteger, bigInteger2);
        }
        this.curve = f2m;
        if (aSN1Sequence.size() == 3) {
            this.seed = ((DERBitString) aSN1Sequence.getObjectAt(2)).getBytes();
        }
    }

    public X9Curve(ECCurve eCCurve) {
        this(eCCurve, null);
    }

    public X9Curve(ECCurve eCCurve, byte[] bArr) {
        this.fieldIdentifier = null;
        this.curve = eCCurve;
        this.seed = Arrays.clone(bArr);
        setFieldIdentifier();
    }

    private void setFieldIdentifier() {
        ASN1ObjectIdentifier aSN1ObjectIdentifier;
        if (ECAlgorithms.isFpCurve(this.curve)) {
            aSN1ObjectIdentifier = prime_field;
        } else if (!ECAlgorithms.isF2mCurve(this.curve)) {
            throw new IllegalArgumentException("This type of ECCurve is not implemented");
        } else {
            aSN1ObjectIdentifier = characteristic_two_field;
        }
        this.fieldIdentifier = aSN1ObjectIdentifier;
    }

    public ECCurve getCurve() {
        return this.curve;
    }

    public byte[] getSeed() {
        return Arrays.clone(this.seed);
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0061  */
    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public org.bouncycastle.asn1.ASN1Primitive toASN1Primitive() {
        /*
            r3 = this;
            org.bouncycastle.asn1.ASN1EncodableVector r0 = new org.bouncycastle.asn1.ASN1EncodableVector
            r1 = 3
            r0.<init>(r1)
            org.bouncycastle.asn1.ASN1ObjectIdentifier r1 = r3.fieldIdentifier
            org.bouncycastle.asn1.ASN1ObjectIdentifier r2 = org.bouncycastle.asn1.p009x9.X9Curve.prime_field
            boolean r1 = r1.equals(r2)
            if (r1 == 0) goto L35
            org.bouncycastle.asn1.x9.X9FieldElement r1 = new org.bouncycastle.asn1.x9.X9FieldElement
            org.bouncycastle.math.ec.ECCurve r2 = r3.curve
            org.bouncycastle.math.ec.ECFieldElement r2 = r2.getA()
            r1.<init>(r2)
            org.bouncycastle.asn1.ASN1Primitive r1 = r1.toASN1Primitive()
            r0.add(r1)
            org.bouncycastle.asn1.x9.X9FieldElement r1 = new org.bouncycastle.asn1.x9.X9FieldElement
            org.bouncycastle.math.ec.ECCurve r2 = r3.curve
            org.bouncycastle.math.ec.ECFieldElement r2 = r2.getB()
            r1.<init>(r2)
        L2d:
            org.bouncycastle.asn1.ASN1Primitive r1 = r1.toASN1Primitive()
            r0.add(r1)
            goto L5d
        L35:
            org.bouncycastle.asn1.ASN1ObjectIdentifier r1 = r3.fieldIdentifier
            org.bouncycastle.asn1.ASN1ObjectIdentifier r2 = org.bouncycastle.asn1.p009x9.X9Curve.characteristic_two_field
            boolean r1 = r1.equals(r2)
            if (r1 == 0) goto L5d
            org.bouncycastle.asn1.x9.X9FieldElement r1 = new org.bouncycastle.asn1.x9.X9FieldElement
            org.bouncycastle.math.ec.ECCurve r2 = r3.curve
            org.bouncycastle.math.ec.ECFieldElement r2 = r2.getA()
            r1.<init>(r2)
            org.bouncycastle.asn1.ASN1Primitive r1 = r1.toASN1Primitive()
            r0.add(r1)
            org.bouncycastle.asn1.x9.X9FieldElement r1 = new org.bouncycastle.asn1.x9.X9FieldElement
            org.bouncycastle.math.ec.ECCurve r2 = r3.curve
            org.bouncycastle.math.ec.ECFieldElement r2 = r2.getB()
            r1.<init>(r2)
            goto L2d
        L5d:
            byte[] r1 = r3.seed
            if (r1 == 0) goto L6b
            org.bouncycastle.asn1.DERBitString r1 = new org.bouncycastle.asn1.DERBitString
            byte[] r2 = r3.seed
            r1.<init>(r2)
            r0.add(r1)
        L6b:
            org.bouncycastle.asn1.DERSequence r1 = new org.bouncycastle.asn1.DERSequence
            r1.<init>(r0)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.asn1.p009x9.X9Curve.toASN1Primitive():org.bouncycastle.asn1.ASN1Primitive");
    }
}