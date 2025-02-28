package org.bouncycastle.asn1;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/DERPrintableString.class */
public class DERPrintableString extends ASN1PrintableString {
    public static DERPrintableString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERPrintableString)) {
            return (DERPrintableString) obj;
        }
        if (obj instanceof ASN1PrintableString) {
            return new DERPrintableString(((ASN1PrintableString) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERPrintableString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERPrintableString getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        ASN1Primitive object = aSN1TaggedObject.getObject();
        return (z || (object instanceof DERPrintableString)) ? getInstance((Object) object) : new DERPrintableString(ASN1OctetString.getInstance(object).getOctets(), true);
    }

    public DERPrintableString(String str) {
        this(str, false);
    }

    public DERPrintableString(String str, boolean z) {
        super(str, z);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DERPrintableString(byte[] bArr, boolean z) {
        super(bArr, z);
    }
}