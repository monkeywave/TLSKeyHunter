package org.bouncycastle.asn1;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/DERVideotexString.class */
public class DERVideotexString extends ASN1VideotexString {
    public static DERVideotexString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERVideotexString)) {
            return (DERVideotexString) obj;
        }
        if (obj instanceof ASN1VideotexString) {
            return new DERVideotexString(((ASN1VideotexString) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERVideotexString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERVideotexString getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        ASN1Primitive object = aSN1TaggedObject.getObject();
        return (z || (object instanceof DERVideotexString)) ? getInstance((Object) object) : new DERVideotexString(ASN1OctetString.getInstance(object).getOctets());
    }

    public DERVideotexString(byte[] bArr) {
        this(bArr, true);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DERVideotexString(byte[] bArr, boolean z) {
        super(bArr, z);
    }
}