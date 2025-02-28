package org.bouncycastle.asn1.pkcs;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/pkcs/RC2CBCParameter.class */
public class RC2CBCParameter extends ASN1Object {
    ASN1Integer version;

    /* renamed from: iv */
    ASN1OctetString f31iv;

    public static RC2CBCParameter getInstance(Object obj) {
        if (obj instanceof RC2CBCParameter) {
            return (RC2CBCParameter) obj;
        }
        if (obj != null) {
            return new RC2CBCParameter(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public RC2CBCParameter(byte[] bArr) {
        this.version = null;
        this.f31iv = new DEROctetString(bArr);
    }

    public RC2CBCParameter(int i, byte[] bArr) {
        this.version = new ASN1Integer(i);
        this.f31iv = new DEROctetString(bArr);
    }

    private RC2CBCParameter(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() == 1) {
            this.version = null;
            this.f31iv = (ASN1OctetString) aSN1Sequence.getObjectAt(0);
            return;
        }
        this.version = (ASN1Integer) aSN1Sequence.getObjectAt(0);
        this.f31iv = (ASN1OctetString) aSN1Sequence.getObjectAt(1);
    }

    public BigInteger getRC2ParameterVersion() {
        if (this.version == null) {
            return null;
        }
        return this.version.getValue();
    }

    public byte[] getIV() {
        return this.f31iv.getOctets();
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
        if (this.version != null) {
            aSN1EncodableVector.add(this.version);
        }
        aSN1EncodableVector.add(this.f31iv);
        return new DERSequence(aSN1EncodableVector);
    }
}