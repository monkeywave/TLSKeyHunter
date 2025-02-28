package org.bouncycastle.asn1.p002ua;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.field.PolynomialExtensionField;
import org.bouncycastle.math.p010ec.ECAlgorithms;
import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.asn1.ua.DSTU4145ECBinary */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ua/DSTU4145ECBinary.class */
public class DSTU4145ECBinary extends ASN1Object {
    BigInteger version;

    /* renamed from: f */
    DSTU4145BinaryField f36f;

    /* renamed from: a */
    ASN1Integer f37a;

    /* renamed from: b */
    ASN1OctetString f38b;

    /* renamed from: n */
    ASN1Integer f39n;

    /* renamed from: bp */
    ASN1OctetString f40bp;

    public DSTU4145ECBinary(ECDomainParameters eCDomainParameters) {
        this.version = BigInteger.valueOf(0L);
        ECCurve curve = eCDomainParameters.getCurve();
        if (!ECAlgorithms.isF2mCurve(curve)) {
            throw new IllegalArgumentException("only binary domain is possible");
        }
        int[] exponentsPresent = ((PolynomialExtensionField) curve.getField()).getMinimalPolynomial().getExponentsPresent();
        if (exponentsPresent.length == 3) {
            this.f36f = new DSTU4145BinaryField(exponentsPresent[2], exponentsPresent[1]);
        } else if (exponentsPresent.length != 5) {
            throw new IllegalArgumentException("curve must have a trinomial or pentanomial basis");
        } else {
            this.f36f = new DSTU4145BinaryField(exponentsPresent[4], exponentsPresent[1], exponentsPresent[2], exponentsPresent[3]);
        }
        this.f37a = new ASN1Integer(curve.getA().toBigInteger());
        this.f38b = new DEROctetString(curve.getB().getEncoded());
        this.f39n = new ASN1Integer(eCDomainParameters.getN());
        this.f40bp = new DEROctetString(DSTU4145PointEncoder.encodePoint(eCDomainParameters.getG()));
    }

    private DSTU4145ECBinary(ASN1Sequence aSN1Sequence) {
        this.version = BigInteger.valueOf(0L);
        int i = 0;
        if (aSN1Sequence.getObjectAt(0) instanceof ASN1TaggedObject) {
            ASN1TaggedObject aSN1TaggedObject = (ASN1TaggedObject) aSN1Sequence.getObjectAt(0);
            if (!aSN1TaggedObject.isExplicit() || 0 != aSN1TaggedObject.getTagNo()) {
                throw new IllegalArgumentException("object parse error");
            }
            this.version = ASN1Integer.getInstance(aSN1TaggedObject.getLoadedObject()).getValue();
            i = 0 + 1;
        }
        this.f36f = DSTU4145BinaryField.getInstance(aSN1Sequence.getObjectAt(i));
        int i2 = i + 1;
        this.f37a = ASN1Integer.getInstance(aSN1Sequence.getObjectAt(i2));
        int i3 = i2 + 1;
        this.f38b = ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(i3));
        int i4 = i3 + 1;
        this.f39n = ASN1Integer.getInstance(aSN1Sequence.getObjectAt(i4));
        this.f40bp = ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(i4 + 1));
    }

    public static DSTU4145ECBinary getInstance(Object obj) {
        if (obj instanceof DSTU4145ECBinary) {
            return (DSTU4145ECBinary) obj;
        }
        if (obj != null) {
            return new DSTU4145ECBinary(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public DSTU4145BinaryField getField() {
        return this.f36f;
    }

    public BigInteger getA() {
        return this.f37a.getValue();
    }

    public byte[] getB() {
        return Arrays.clone(this.f38b.getOctets());
    }

    public BigInteger getN() {
        return this.f39n.getValue();
    }

    public byte[] getG() {
        return Arrays.clone(this.f40bp.getOctets());
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(6);
        if (0 != this.version.compareTo(BigInteger.valueOf(0L))) {
            aSN1EncodableVector.add(new DERTaggedObject(true, 0, (ASN1Encodable) new ASN1Integer(this.version)));
        }
        aSN1EncodableVector.add(this.f36f);
        aSN1EncodableVector.add(this.f37a);
        aSN1EncodableVector.add(this.f38b);
        aSN1EncodableVector.add(this.f39n);
        aSN1EncodableVector.add(this.f40bp);
        return new DERSequence(aSN1EncodableVector);
    }
}