package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ASN1Primitive.class */
public abstract class ASN1Primitive extends ASN1Object {
    @Override // org.bouncycastle.asn1.ASN1Object
    public void encodeTo(OutputStream outputStream) throws IOException {
        ASN1OutputStream create = ASN1OutputStream.create(outputStream);
        create.writePrimitive(this, true);
        create.flushInternal();
    }

    @Override // org.bouncycastle.asn1.ASN1Object
    public void encodeTo(OutputStream outputStream, String str) throws IOException {
        ASN1OutputStream create = ASN1OutputStream.create(outputStream, str);
        create.writePrimitive(this, true);
        create.flushInternal();
    }

    public static ASN1Primitive fromByteArray(byte[] bArr) throws IOException {
        ASN1InputStream aSN1InputStream = new ASN1InputStream(bArr);
        try {
            ASN1Primitive readObject = aSN1InputStream.readObject();
            if (aSN1InputStream.available() != 0) {
                throw new IOException("Extra data detected in stream");
            }
            return readObject;
        } catch (ClassCastException e) {
            throw new IOException("cannot recognise object in stream");
        }
    }

    @Override // org.bouncycastle.asn1.ASN1Object
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof ASN1Encodable) && asn1Equals(((ASN1Encodable) obj).toASN1Primitive());
    }

    public final boolean equals(ASN1Encodable aSN1Encodable) {
        return this == aSN1Encodable || (null != aSN1Encodable && asn1Equals(aSN1Encodable.toASN1Primitive()));
    }

    public final boolean equals(ASN1Primitive aSN1Primitive) {
        return this == aSN1Primitive || asn1Equals(aSN1Primitive);
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public final ASN1Primitive toASN1Primitive() {
        return this;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1Primitive toDERObject() {
        return this;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1Primitive toDLObject() {
        return this;
    }

    @Override // org.bouncycastle.asn1.ASN1Object
    public abstract int hashCode();

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract boolean encodeConstructed();

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract int encodedLength(boolean z) throws IOException;

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void encode(ASN1OutputStream aSN1OutputStream, boolean z) throws IOException;

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract boolean asn1Equals(ASN1Primitive aSN1Primitive);
}