package org.bouncycastle.asn1.p003x9;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.math.p010ec.ECAlgorithms;
import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.asn1.x9.X9Curve */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/x9/X9Curve.class */
public class X9Curve extends ASN1Object implements X9ObjectIdentifiers {
    private ECCurve curve;
    private byte[] seed;
    private ASN1ObjectIdentifier fieldIdentifier;

    public X9Curve(ECCurve eCCurve) {
        this(eCCurve, null);
    }

    public X9Curve(ECCurve eCCurve, byte[] bArr) {
        this.fieldIdentifier = null;
        this.curve = eCCurve;
        this.seed = Arrays.clone(bArr);
        setFieldIdentifier();
    }

    public X9Curve(X9FieldID x9FieldID, BigInteger bigInteger, BigInteger bigInteger2, ASN1Sequence aSN1Sequence) {
        int intValueExact;
        this.fieldIdentifier = null;
        this.fieldIdentifier = x9FieldID.getIdentifier();
        if (this.fieldIdentifier.equals((ASN1Primitive) prime_field)) {
            this.curve = new ECCurve.C0277Fp(((ASN1Integer) x9FieldID.getParameters()).getValue(), new BigInteger(1, ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(0)).getOctets()), new BigInteger(1, ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(1)).getOctets()), bigInteger, bigInteger2);
        } else if (!this.fieldIdentifier.equals((ASN1Primitive) characteristic_two_field)) {
            throw new IllegalArgumentException("This type of ECCurve is not implemented");
        } else {
            ASN1Sequence aSN1Sequence2 = ASN1Sequence.getInstance(x9FieldID.getParameters());
            int intValueExact2 = ((ASN1Integer) aSN1Sequence2.getObjectAt(0)).intValueExact();
            ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) aSN1Sequence2.getObjectAt(1);
            int i = 0;
            int i2 = 0;
            if (aSN1ObjectIdentifier.equals((ASN1Primitive) tpBasis)) {
                intValueExact = ASN1Integer.getInstance(aSN1Sequence2.getObjectAt(2)).intValueExact();
            } else if (!aSN1ObjectIdentifier.equals((ASN1Primitive) ppBasis)) {
                throw new IllegalArgumentException("This type of EC basis is not implemented");
            } else {
                ASN1Sequence aSN1Sequence3 = ASN1Sequence.getInstance(aSN1Sequence2.getObjectAt(2));
                intValueExact = ASN1Integer.getInstance(aSN1Sequence3.getObjectAt(0)).intValueExact();
                i = ASN1Integer.getInstance(aSN1Sequence3.getObjectAt(1)).intValueExact();
                i2 = ASN1Integer.getInstance(aSN1Sequence3.getObjectAt(2)).intValueExact();
            }
            this.curve = new ECCurve.F2m(intValueExact2, intValueExact, i, i2, new BigInteger(1, ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(0)).getOctets()), new BigInteger(1, ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(1)).getOctets()), bigInteger, bigInteger2);
        }
        if (aSN1Sequence.size() == 3) {
            this.seed = ((DERBitString) aSN1Sequence.getObjectAt(2)).getBytes();
        }
    }

    private void setFieldIdentifier() {
        if (ECAlgorithms.isFpCurve(this.curve)) {
            this.fieldIdentifier = prime_field;
        } else if (!ECAlgorithms.isF2mCurve(this.curve)) {
            throw new IllegalArgumentException("This type of ECCurve is not implemented");
        } else {
            this.fieldIdentifier = characteristic_two_field;
        }
    }

    public ECCurve getCurve() {
        return this.curve;
    }

    public byte[] getSeed() {
        return Arrays.clone(this.seed);
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(3);
        if (this.fieldIdentifier.equals((ASN1Primitive) prime_field)) {
            aSN1EncodableVector.add(new X9FieldElement(this.curve.getA()).toASN1Primitive());
            aSN1EncodableVector.add(new X9FieldElement(this.curve.getB()).toASN1Primitive());
        } else if (this.fieldIdentifier.equals((ASN1Primitive) characteristic_two_field)) {
            aSN1EncodableVector.add(new X9FieldElement(this.curve.getA()).toASN1Primitive());
            aSN1EncodableVector.add(new X9FieldElement(this.curve.getB()).toASN1Primitive());
        }
        if (this.seed != null) {
            aSN1EncodableVector.add(new DERBitString(this.seed));
        }
        return new DERSequence(aSN1EncodableVector);
    }
}