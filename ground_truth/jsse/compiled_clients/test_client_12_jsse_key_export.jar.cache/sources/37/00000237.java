package org.bouncycastle.asn1;

import java.io.IOException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/DERTaggedObject.class */
public class DERTaggedObject extends ASN1TaggedObject {
    public DERTaggedObject(int i, ASN1Encodable aSN1Encodable) {
        super(true, i, aSN1Encodable);
    }

    public DERTaggedObject(int i, int i2, ASN1Encodable aSN1Encodable) {
        super(true, i, i2, aSN1Encodable);
    }

    public DERTaggedObject(boolean z, int i, ASN1Encodable aSN1Encodable) {
        super(z, i, aSN1Encodable);
    }

    public DERTaggedObject(boolean z, int i, int i2, ASN1Encodable aSN1Encodable) {
        super(z, i, i2, aSN1Encodable);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DERTaggedObject(int i, int i2, int i3, ASN1Encodable aSN1Encodable) {
        super(i, i2, i3, aSN1Encodable);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return isExplicit() || this.obj.toASN1Primitive().toDERObject().encodeConstructed();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public int encodedLength(boolean z) throws IOException {
        ASN1Primitive dERObject = this.obj.toASN1Primitive().toDERObject();
        boolean isExplicit = isExplicit();
        int encodedLength = dERObject.encodedLength(isExplicit);
        if (isExplicit) {
            encodedLength += ASN1OutputStream.getLengthOfDL(encodedLength);
        }
        return encodedLength + (z ? ASN1OutputStream.getLengthOfIdentifier(this.tagNo) : 0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public void encode(ASN1OutputStream aSN1OutputStream, boolean z) throws IOException {
        ASN1Primitive dERObject = this.obj.toASN1Primitive().toDERObject();
        boolean isExplicit = isExplicit();
        if (z) {
            int i = this.tagClass;
            if (isExplicit || dERObject.encodeConstructed()) {
                i |= 32;
            }
            aSN1OutputStream.writeIdentifier(true, i, this.tagNo);
        }
        if (isExplicit) {
            aSN1OutputStream.writeDL(dERObject.encodedLength(true));
        }
        dERObject.encode(aSN1OutputStream.getDERSubStream(), isExplicit);
    }

    @Override // org.bouncycastle.asn1.ASN1TaggedObject
    String getASN1Encoding() {
        return ASN1Encoding.DER;
    }

    @Override // org.bouncycastle.asn1.ASN1TaggedObject
    ASN1Sequence rebuildConstructed(ASN1Primitive aSN1Primitive) {
        return new DERSequence(aSN1Primitive);
    }

    @Override // org.bouncycastle.asn1.ASN1TaggedObject
    ASN1TaggedObject replaceTag(int i, int i2) {
        return new DERTaggedObject(this.explicitness, i, i2, this.obj);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1TaggedObject, org.bouncycastle.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        return this;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1TaggedObject, org.bouncycastle.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return this;
    }
}