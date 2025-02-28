package org.bouncycastle.asn1;

import java.io.IOException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/DLBitString.class */
public class DLBitString extends ASN1BitString {
    public DLBitString(byte[] bArr) {
        this(bArr, 0);
    }

    public DLBitString(byte b, int i) {
        super(b, i);
    }

    public DLBitString(byte[] bArr, int i) {
        super(bArr, i);
    }

    public DLBitString(int i) {
        super(getBytes(i), getPadBits(i));
    }

    public DLBitString(ASN1Encodable aSN1Encodable) throws IOException {
        super(aSN1Encodable.toASN1Primitive().getEncoded(ASN1Encoding.DER), 0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DLBitString(byte[] bArr, boolean z) {
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
        aSN1OutputStream.writeEncodingDL(z, 3, this.contents);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1BitString, org.bouncycastle.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return this;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int encodedLength(boolean z, int i) {
        return ASN1OutputStream.getLengthOfEncodingDL(z, i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void encode(ASN1OutputStream aSN1OutputStream, boolean z, byte[] bArr, int i, int i2) throws IOException {
        aSN1OutputStream.writeEncodingDL(z, 3, bArr, i, i2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void encode(ASN1OutputStream aSN1OutputStream, boolean z, byte b, byte[] bArr, int i, int i2) throws IOException {
        aSN1OutputStream.writeEncodingDL(z, 3, b, bArr, i, i2);
    }

    static DLBitString fromOctetString(ASN1OctetString aSN1OctetString) {
        return new DLBitString(aSN1OctetString.getOctets(), true);
    }
}