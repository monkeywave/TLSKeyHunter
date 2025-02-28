package org.bouncycastle.asn1;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/DERNumericString.class */
public class DERNumericString extends ASN1NumericString {
    public static DERNumericString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERNumericString)) {
            return (DERNumericString) obj;
        }
        if (obj instanceof ASN1NumericString) {
            return new DERNumericString(((ASN1NumericString) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERNumericString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERNumericString getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        ASN1Primitive object = aSN1TaggedObject.getObject();
        return (z || (object instanceof DERNumericString)) ? getInstance((Object) object) : new DERNumericString(ASN1OctetString.getInstance(object).getOctets(), true);
    }

    public DERNumericString(String str) {
        this(str, false);
    }

    public DERNumericString(String str, boolean z) {
        super(str, z);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DERNumericString(byte[] bArr, boolean z) {
        super(bArr, z);
    }
}