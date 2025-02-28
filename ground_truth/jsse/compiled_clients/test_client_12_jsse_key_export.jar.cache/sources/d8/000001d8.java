package org.bouncycastle.asn1;

import java.io.IOException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ASN1Null.class */
public abstract class ASN1Null extends ASN1Primitive {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1Null.class, 5) { // from class: org.bouncycastle.asn1.ASN1Null.1
        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // org.bouncycastle.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString dEROctetString) {
            return ASN1Null.createPrimitive(dEROctetString.getOctets());
        }
    };

    public static ASN1Null getInstance(Object obj) {
        if (obj instanceof ASN1Null) {
            return (ASN1Null) obj;
        }
        if (obj != null) {
            try {
                return (ASN1Null) TYPE.fromByteArray((byte[]) obj);
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to construct NULL from byte[]: " + e.getMessage());
            }
        }
        return null;
    }

    public static ASN1Null getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return (ASN1Null) TYPE.getContextInstance(aSN1TaggedObject, z);
    }

    @Override // org.bouncycastle.asn1.ASN1Primitive, org.bouncycastle.asn1.ASN1Object
    public int hashCode() {
        return -1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public boolean asn1Equals(ASN1Primitive aSN1Primitive) {
        return aSN1Primitive instanceof ASN1Null;
    }

    public String toString() {
        return "NULL";
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1Null createPrimitive(byte[] bArr) {
        if (0 != bArr.length) {
            throw new IllegalStateException("malformed NULL encoding encountered");
        }
        return DERNull.INSTANCE;
    }
}