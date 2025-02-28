package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/* loaded from: classes.dex */
public class KemCiphertextInfo extends ASN1Object {

    /* renamed from: ct */
    private final ASN1OctetString f240ct;
    private final AlgorithmIdentifier kem;

    private KemCiphertextInfo(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() != 2) {
            throw new IllegalArgumentException("sequence size should 2");
        }
        this.kem = AlgorithmIdentifier.getInstance(aSN1Sequence.getObjectAt(0));
        this.f240ct = ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(1));
    }

    public KemCiphertextInfo(AlgorithmIdentifier algorithmIdentifier, ASN1OctetString aSN1OctetString) {
        this.kem = algorithmIdentifier;
        this.f240ct = aSN1OctetString;
    }

    public static KemCiphertextInfo getInstance(Object obj) {
        if (obj instanceof KemCiphertextInfo) {
            return (KemCiphertextInfo) obj;
        }
        if (obj != null) {
            return new KemCiphertextInfo(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public ASN1OctetString getCt() {
        return this.f240ct;
    }

    public AlgorithmIdentifier getKem() {
        return this.kem;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
        aSN1EncodableVector.add(this.kem);
        aSN1EncodableVector.add(this.f240ct);
        return new DERSequence(aSN1EncodableVector);
    }
}