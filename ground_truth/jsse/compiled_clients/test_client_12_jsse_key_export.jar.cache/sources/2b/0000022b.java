package org.bouncycastle.asn1;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/DERGraphicString.class */
public class DERGraphicString extends ASN1GraphicString {
    public static DERGraphicString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERGraphicString)) {
            return (DERGraphicString) obj;
        }
        if (obj instanceof ASN1GraphicString) {
            return new DERGraphicString(((ASN1GraphicString) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERGraphicString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERGraphicString getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        ASN1Primitive object = aSN1TaggedObject.getObject();
        return (z || (object instanceof DERGraphicString)) ? getInstance((Object) object) : new DERGraphicString(ASN1OctetString.getInstance(object).getOctets());
    }

    public DERGraphicString(byte[] bArr) {
        this(bArr, true);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DERGraphicString(byte[] bArr, boolean z) {
        super(bArr, z);
    }
}