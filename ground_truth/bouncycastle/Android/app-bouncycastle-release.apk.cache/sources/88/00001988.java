package org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.util.Arrays;

/* loaded from: classes.dex */
public abstract class ASN1UniversalString extends ASN1Primitive implements ASN1String {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1UniversalString.class, 28) { // from class: org.bouncycastle.asn1.ASN1UniversalString.1
        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // org.bouncycastle.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString dEROctetString) {
            return ASN1UniversalString.createPrimitive(dEROctetString.getOctets());
        }
    };
    private static final char[] table = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    final byte[] contents;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1UniversalString(byte[] bArr, boolean z) {
        this.contents = z ? Arrays.clone(bArr) : bArr;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1UniversalString createPrimitive(byte[] bArr) {
        return new DERUniversalString(bArr, false);
    }

    private static void encodeHexByte(StringBuffer stringBuffer, int i) {
        char[] cArr = table;
        stringBuffer.append(cArr[(i >>> 4) & 15]);
        stringBuffer.append(cArr[i & 15]);
    }

    private static void encodeHexDL(StringBuffer stringBuffer, int i) {
        int i2;
        if (i < 128) {
            encodeHexByte(stringBuffer, i);
            return;
        }
        byte[] bArr = new byte[5];
        int i3 = 5;
        while (true) {
            i2 = i3 - 1;
            bArr[i2] = (byte) i;
            i >>>= 8;
            if (i == 0) {
                break;
            }
            i3 = i2;
        }
        int i4 = i3 - 2;
        bArr[i4] = (byte) ((5 - i2) | 128);
        while (true) {
            int i5 = i4 + 1;
            encodeHexByte(stringBuffer, bArr[i4]);
            if (i5 >= 5) {
                return;
            }
            i4 = i5;
        }
    }

    public static ASN1UniversalString getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1UniversalString)) {
            return (ASN1UniversalString) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive aSN1Primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (aSN1Primitive instanceof ASN1UniversalString) {
                return (ASN1UniversalString) aSN1Primitive;
            }
        }
        if (obj instanceof byte[]) {
            try {
                return (ASN1UniversalString) TYPE.fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error getInstance: " + e.toString());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1UniversalString getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return (ASN1UniversalString) TYPE.getContextInstance(aSN1TaggedObject, z);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public final boolean asn1Equals(ASN1Primitive aSN1Primitive) {
        if (aSN1Primitive instanceof ASN1UniversalString) {
            return Arrays.areEqual(this.contents, ((ASN1UniversalString) aSN1Primitive).contents);
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public final void encode(ASN1OutputStream aSN1OutputStream, boolean z) throws IOException {
        aSN1OutputStream.writeEncodingDL(z, 28, this.contents);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public final boolean encodeConstructed() {
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public final int encodedLength(boolean z) {
        return ASN1OutputStream.getLengthOfEncodingDL(z, this.contents.length);
    }

    public final byte[] getOctets() {
        return Arrays.clone(this.contents);
    }

    @Override // org.bouncycastle.asn1.ASN1String
    public final String getString() {
        int length = this.contents.length;
        StringBuffer stringBuffer = new StringBuffer(((ASN1OutputStream.getLengthOfDL(length) + length) * 2) + 3);
        stringBuffer.append("#1C");
        encodeHexDL(stringBuffer, length);
        for (int i = 0; i < length; i++) {
            encodeHexByte(stringBuffer, this.contents[i]);
        }
        return stringBuffer.toString();
    }

    @Override // org.bouncycastle.asn1.ASN1Primitive, org.bouncycastle.asn1.ASN1Object
    public final int hashCode() {
        return Arrays.hashCode(this.contents);
    }

    public String toString() {
        return getString();
    }
}