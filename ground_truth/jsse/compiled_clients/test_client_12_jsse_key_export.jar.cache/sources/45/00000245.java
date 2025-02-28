package org.bouncycastle.asn1;

import java.io.IOException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/DLSet.class */
public class DLSet extends ASN1Set {
    private int contentsLength;

    public DLSet() {
        this.contentsLength = -1;
    }

    public DLSet(ASN1Encodable aSN1Encodable) {
        super(aSN1Encodable);
        this.contentsLength = -1;
    }

    public DLSet(ASN1EncodableVector aSN1EncodableVector) {
        super(aSN1EncodableVector, false);
        this.contentsLength = -1;
    }

    public DLSet(ASN1Encodable[] aSN1EncodableArr) {
        super(aSN1EncodableArr, false);
        this.contentsLength = -1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DLSet(boolean z, ASN1Encodable[] aSN1EncodableArr) {
        super(z, aSN1EncodableArr);
        this.contentsLength = -1;
    }

    private int getContentsLength() throws IOException {
        if (this.contentsLength < 0) {
            int length = this.elements.length;
            int i = 0;
            for (int i2 = 0; i2 < length; i2++) {
                i += this.elements[i2].toASN1Primitive().toDLObject().encodedLength(true);
            }
            this.contentsLength = i;
        }
        return this.contentsLength;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public int encodedLength(boolean z) throws IOException {
        return ASN1OutputStream.getLengthOfEncodingDL(z, getContentsLength());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public void encode(ASN1OutputStream aSN1OutputStream, boolean z) throws IOException {
        aSN1OutputStream.writeIdentifier(z, 49);
        DLOutputStream dLSubStream = aSN1OutputStream.getDLSubStream();
        int length = this.elements.length;
        if (this.contentsLength >= 0 || length > 16) {
            aSN1OutputStream.writeDL(getContentsLength());
            for (int i = 0; i < length; i++) {
                dLSubStream.writePrimitive(this.elements[i].toASN1Primitive(), true);
            }
            return;
        }
        int i2 = 0;
        ASN1Primitive[] aSN1PrimitiveArr = new ASN1Primitive[length];
        for (int i3 = 0; i3 < length; i3++) {
            ASN1Primitive dLObject = this.elements[i3].toASN1Primitive().toDLObject();
            aSN1PrimitiveArr[i3] = dLObject;
            i2 += dLObject.encodedLength(true);
        }
        this.contentsLength = i2;
        aSN1OutputStream.writeDL(i2);
        for (int i4 = 0; i4 < length; i4++) {
            dLSubStream.writePrimitive(aSN1PrimitiveArr[i4], true);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Set, org.bouncycastle.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return this;
    }
}