package org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/DERBitString.class */
public class DERBitString extends ASN1BitString {
    public static DERBitString convert(ASN1BitString aSN1BitString) {
        return (DERBitString) aSN1BitString.toDERObject();
    }

    public static DERBitString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERBitString)) {
            return (DERBitString) obj;
        }
        if (obj instanceof ASN1BitString) {
            return convert((ASN1BitString) obj);
        }
        if (obj instanceof byte[]) {
            try {
                return convert((ASN1BitString) fromByteArray((byte[]) obj));
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERBitString getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        ASN1Primitive object = aSN1TaggedObject.getObject();
        return (z || (object instanceof DERBitString)) ? getInstance((Object) object) : fromOctetString(ASN1OctetString.getInstance(object));
    }

    public DERBitString(byte[] bArr) {
        this(bArr, 0);
    }

    public DERBitString(byte b, int i) {
        super(b, i);
    }

    public DERBitString(byte[] bArr, int i) {
        super(bArr, i);
    }

    public DERBitString(int i) {
        super(getBytes(i), getPadBits(i));
    }

    public DERBitString(ASN1Encodable aSN1Encodable) throws IOException {
        super(aSN1Encodable.toASN1Primitive().getEncoded(ASN1Encoding.DER), 0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DERBitString(byte[] bArr, boolean z) {
        super(bArr, z);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public int encodedLength(boolean z) {
        return ASN1OutputStream.getLengthOfEncodingDL(z, this.contents.length);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public void encode(ASN1OutputStream aSN1OutputStream, boolean z) throws IOException {
        int i = this.contents[0] & 255;
        int length = this.contents.length - 1;
        byte b = this.contents[length];
        byte b2 = (byte) (this.contents[length] & (GF2Field.MASK << i));
        if (b == b2) {
            aSN1OutputStream.writeEncodingDL(z, 3, this.contents);
        } else {
            aSN1OutputStream.writeEncodingDL(z, 3, this.contents, 0, length, b2);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1BitString, org.bouncycastle.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        return this;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1BitString, org.bouncycastle.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return this;
    }

    static DERBitString fromOctetString(ASN1OctetString aSN1OctetString) {
        return new DERBitString(aSN1OctetString.getOctets(), true);
    }
}