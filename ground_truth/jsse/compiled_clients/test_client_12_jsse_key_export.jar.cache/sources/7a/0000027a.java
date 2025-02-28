package org.bouncycastle.asn1.misc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/misc/IDEACBCPar.class */
public class IDEACBCPar extends ASN1Object {

    /* renamed from: iv */
    ASN1OctetString f22iv;

    public static IDEACBCPar getInstance(Object obj) {
        if (obj instanceof IDEACBCPar) {
            return (IDEACBCPar) obj;
        }
        if (obj != null) {
            return new IDEACBCPar(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public IDEACBCPar(byte[] bArr) {
        this.f22iv = new DEROctetString(bArr);
    }

    private IDEACBCPar(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() == 1) {
            this.f22iv = (ASN1OctetString) aSN1Sequence.getObjectAt(0);
        } else {
            this.f22iv = null;
        }
    }

    public byte[] getIV() {
        if (this.f22iv != null) {
            return Arrays.clone(this.f22iv.getOctets());
        }
        return null;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(1);
        if (this.f22iv != null) {
            aSN1EncodableVector.add(this.f22iv);
        }
        return new DERSequence(aSN1EncodableVector);
    }
}