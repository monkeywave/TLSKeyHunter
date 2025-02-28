package org.bouncycastle.asn1;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ASN1Tag.class */
final class ASN1Tag {
    private final int tagClass;
    private final int tagNumber;

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1Tag create(int i, int i2) {
        return new ASN1Tag(i, i2);
    }

    private ASN1Tag(int i, int i2) {
        this.tagClass = i;
        this.tagNumber = i2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getTagClass() {
        return this.tagClass;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getTagNumber() {
        return this.tagNumber;
    }
}