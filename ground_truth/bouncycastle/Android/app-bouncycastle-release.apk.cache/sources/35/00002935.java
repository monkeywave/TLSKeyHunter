package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.pqc.legacy.math.linearalgebra.GF2Matrix;

/* loaded from: classes2.dex */
public class McEliecePublicKey extends ASN1Object {

    /* renamed from: g */
    private final GF2Matrix f1191g;

    /* renamed from: n */
    private final int f1192n;

    /* renamed from: t */
    private final int f1193t;

    public McEliecePublicKey(int i, int i2, GF2Matrix gF2Matrix) {
        this.f1192n = i;
        this.f1193t = i2;
        this.f1191g = new GF2Matrix(gF2Matrix);
    }

    private McEliecePublicKey(ASN1Sequence aSN1Sequence) {
        this.f1192n = ((ASN1Integer) aSN1Sequence.getObjectAt(0)).intValueExact();
        this.f1193t = ((ASN1Integer) aSN1Sequence.getObjectAt(1)).intValueExact();
        this.f1191g = new GF2Matrix(((ASN1OctetString) aSN1Sequence.getObjectAt(2)).getOctets());
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

    public GF2Matrix getG() {
        return new GF2Matrix(this.f1191g);
    }

    public int getN() {
        return this.f1192n;
    }

    public int getT() {
        return this.f1193t;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        aSN1EncodableVector.add(new ASN1Integer(this.f1192n));
        aSN1EncodableVector.add(new ASN1Integer(this.f1193t));
        aSN1EncodableVector.add(new DEROctetString(this.f1191g.getEncoded()));
        return new DERSequence(aSN1EncodableVector);
    }
}