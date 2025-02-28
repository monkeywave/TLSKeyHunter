package org.bouncycastle.asn1;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/DERUniversalString.class */
public class DERUniversalString extends ASN1UniversalString {
    public static DERUniversalString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERUniversalString)) {
            return (DERUniversalString) obj;
        }
        if (obj instanceof ASN1UniversalString) {
            return new DERUniversalString(((ASN1UniversalString) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERUniversalString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error getInstance: " + e.toString());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERUniversalString getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        ASN1Primitive object = aSN1TaggedObject.getObject();
        return (z || (object instanceof DERUniversalString)) ? getInstance((Object) object) : new DERUniversalString(ASN1OctetString.getInstance(object).getOctets(), true);
    }

    public DERUniversalString(byte[] bArr) {
        this(bArr, true);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DERUniversalString(byte[] bArr, boolean z) {
        super(bArr, z);
    }
}