package org.bouncycastle.asn1;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/DERGeneralString.class */
public class DERGeneralString extends ASN1GeneralString {
    public static DERGeneralString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERGeneralString)) {
            return (DERGeneralString) obj;
        }
        if (obj instanceof ASN1GeneralString) {
            return new DERGeneralString(((ASN1GeneralString) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERGeneralString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERGeneralString getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        ASN1Primitive object = aSN1TaggedObject.getObject();
        return (z || (object instanceof DERGeneralString)) ? getInstance((Object) object) : new DERGeneralString(ASN1OctetString.getInstance(object).getOctets(), true);
    }

    public DERGeneralString(String str) {
        super(str);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DERGeneralString(byte[] bArr, boolean z) {
        super(bArr, z);
    }
}