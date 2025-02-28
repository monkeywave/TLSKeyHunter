package org.bouncycastle.asn1.eac;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/* loaded from: classes.dex */
class EACTagged {
    EACTagged() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1TaggedObject create(int i, ASN1Sequence aSN1Sequence) {
        return new DERTaggedObject(false, 64, i, (ASN1Encodable) aSN1Sequence);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1TaggedObject create(int i, PublicKeyDataObject publicKeyDataObject) {
        return new DERTaggedObject(false, 64, i, (ASN1Encodable) publicKeyDataObject);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1TaggedObject create(int i, byte[] bArr) {
        return new DERTaggedObject(false, 64, i, (ASN1Encodable) new DEROctetString(bArr));
    }
}