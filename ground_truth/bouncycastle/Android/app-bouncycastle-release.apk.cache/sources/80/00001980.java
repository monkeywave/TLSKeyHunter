package org.bouncycastle.asn1;

/* loaded from: classes.dex */
final class ASN1Tag {
    private final int tagClass;
    private final int tagNumber;

    private ASN1Tag(int i, int i2) {
        this.tagClass = i;
        this.tagNumber = i2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1Tag create(int i, int i2) {
        return new ASN1Tag(i, i2);
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