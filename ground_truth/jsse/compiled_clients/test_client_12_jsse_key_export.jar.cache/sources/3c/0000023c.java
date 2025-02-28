package org.bouncycastle.asn1;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/DERVisibleString.class */
public class DERVisibleString extends ASN1VisibleString {
    public static DERVisibleString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERVisibleString)) {
            return (DERVisibleString) obj;
        }
        if (obj instanceof ASN1VisibleString) {
            return new DERVisibleString(((ASN1VisibleString) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERVisibleString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERVisibleString getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        ASN1Primitive object = aSN1TaggedObject.getObject();
        return (z || (object instanceof DERVisibleString)) ? getInstance((Object) object) : new DERVisibleString(ASN1OctetString.getInstance(object).getOctets(), true);
    }

    public DERVisibleString(String str) {
        super(str);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DERVisibleString(byte[] bArr, boolean z) {
        super(bArr, z);
    }
}