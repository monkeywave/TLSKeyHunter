package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/asn1/McEliecePublicKey.class */
public class McEliecePublicKey extends ASN1Object {

    /* renamed from: n */
    private final int f803n;

    /* renamed from: t */
    private final int f804t;

    /* renamed from: g */
    private final GF2Matrix f805g;

    public McEliecePublicKey(int i, int i2, GF2Matrix gF2Matrix) {
        this.f803n = i;
        this.f804t = i2;
        this.f805g = new GF2Matrix(gF2Matrix);
    }

    private McEliecePublicKey(ASN1Sequence aSN1Sequence) {
        this.f803n = ((ASN1Integer) aSN1Sequence.getObjectAt(0)).intValueExact();
        this.f804t = ((ASN1Integer) aSN1Sequence.getObjectAt(1)).intValueExact();
        this.f805g = new GF2Matrix(((ASN1OctetString) aSN1Sequence.getObjectAt(2)).getOctets());
    }

    public int getN() {
        return this.f803n;
    }

    public int getT() {
        return this.f804t;
    }

    public GF2Matrix getG() {
        return new GF2Matrix(this.f805g);
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        aSN1EncodableVector.add(new ASN1Integer(this.f803n));
        aSN1EncodableVector.add(new ASN1Integer(this.f804t));
        aSN1EncodableVector.add(new DEROctetString(this.f805g.getEncoded()));
        return new DERSequence(aSN1EncodableVector);
    }

    public static McEliecePublicKey getInstance(Object obj) {
        if (obj instanceof McEliecePublicKey) {
            return (McEliecePublicKey) obj;
        }
        if (obj != null) {
            return new McEliecePublicKey(ASN1Sequence.getInstance(obj));
        }
        return null;
    }
}