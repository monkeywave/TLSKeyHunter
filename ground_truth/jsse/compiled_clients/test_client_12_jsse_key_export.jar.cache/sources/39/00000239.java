package org.bouncycastle.asn1;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/DERUTF8String.class */
public class DERUTF8String extends ASN1UTF8String {
    public static DERUTF8String getInstance(Object obj) {
        if (obj == null || (obj instanceof DERUTF8String)) {
            return (DERUTF8String) obj;
        }
        if (obj instanceof ASN1UTF8String) {
            return new DERUTF8String(((ASN1UTF8String) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERUTF8String) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERUTF8String getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        ASN1Primitive object = aSN1TaggedObject.getObject();
        return (z || (object instanceof DERUTF8String)) ? getInstance((Object) object) : new DERUTF8String(ASN1OctetString.getInstance(object).getOctets(), true);
    }

    public DERUTF8String(String str) {
        super(str);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DERUTF8String(byte[] bArr, boolean z) {
        super(bArr, z);
    }
}