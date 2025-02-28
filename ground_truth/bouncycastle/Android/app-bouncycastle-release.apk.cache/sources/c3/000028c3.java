package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class HashedId extends ASN1Object {

    /* renamed from: id */
    private final byte[] f1165id;

    /* JADX INFO: Access modifiers changed from: protected */
    public HashedId(byte[] bArr) {
        this.f1165id = Arrays.clone(bArr);
    }

    @Override // org.bouncycastle.asn1.ASN1Object
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && getClass() == obj.getClass() && super.equals(obj)) {
            return java.util.Arrays.equals(this.f1165id, ((HashedId) obj).f1165id);
        }
        return false;
    }

    public byte[] getHashBytes() {
        return Arrays.clone(this.f1165id);
    }

    @Override // org.bouncycastle.asn1.ASN1Object
    public int hashCode() {
        return (super.hashCode() * 31) + java.util.Arrays.hashCode(this.f1165id);
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DEROctetString(this.f1165id);
    }
}