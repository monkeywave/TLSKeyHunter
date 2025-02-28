package org.bouncycastle.asn1;

import java.io.IOException;
import javassist.bytecode.Opcode;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ASN1NumericString.class */
public abstract class ASN1NumericString extends ASN1Primitive implements ASN1String {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1NumericString.class, 18) { // from class: org.bouncycastle.asn1.ASN1NumericString.1
        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // org.bouncycastle.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString dEROctetString) {
            return ASN1NumericString.createPrimitive(dEROctetString.getOctets());
        }
    };
    final byte[] contents;

    public static ASN1NumericString getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1NumericString)) {
            return (ASN1NumericString) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive aSN1Primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (aSN1Primitive instanceof ASN1NumericString) {
                return (ASN1NumericString) aSN1Primitive;
            }
        }
        if (obj instanceof byte[]) {
            try {
                return (ASN1NumericString) TYPE.fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1NumericString getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return (ASN1NumericString) TYPE.getContextInstance(aSN1TaggedObject, z);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1NumericString(String str, boolean z) {
        if (z && !isNumericString(str)) {
            throw new IllegalArgumentException("string contains illegal characters");
        }
        this.contents = Strings.toByteArray(str);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1NumericString(byte[] bArr, boolean z) {
        this.contents = z ? Arrays.clone(bArr) : bArr;
    }

    @Override // org.bouncycastle.asn1.ASN1String
    public final String getString() {
        return Strings.fromByteArray(this.contents);
    }

    public String toString() {
        return getString();
    }

    public final byte[] getOctets() {
        return Arrays.clone(this.contents);
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

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public final void encode(ASN1OutputStream aSN1OutputStream, boolean z) throws IOException {
        aSN1OutputStream.writeEncodingDL(z, 18, this.contents);
    }

    @Override // org.bouncycastle.asn1.ASN1Primitive, org.bouncycastle.asn1.ASN1Object
    public final int hashCode() {
        return Arrays.hashCode(this.contents);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public final boolean asn1Equals(ASN1Primitive aSN1Primitive) {
        if (aSN1Primitive instanceof ASN1NumericString) {
            return Arrays.areEqual(this.contents, ((ASN1NumericString) aSN1Primitive).contents);
        }
        return false;
    }

    public static boolean isNumericString(String str) {
        for (int length = str.length() - 1; length >= 0; length--) {
            char charAt = str.charAt(length);
            if (charAt > 127) {
                return false;
            }
            if (('0' > charAt || charAt > '9') && charAt != ' ') {
                return false;
            }
        }
        return true;
    }

    static boolean isNumericString(byte[] bArr) {
        for (byte b : bArr) {
            switch (b) {
                case 32:
                case 48:
                case 49:
                case 50:
                case 51:
                case 52:
                case 53:
                case 54:
                case 55:
                case 56:
                case 57:
                case Opcode.LLOAD_3 /* 33 */:
                case Opcode.FLOAD_0 /* 34 */:
                case 35:
                case Opcode.FLOAD_2 /* 36 */:
                case Opcode.FLOAD_3 /* 37 */:
                case Opcode.DLOAD_0 /* 38 */:
                case Opcode.DLOAD_1 /* 39 */:
                case 40:
                case Opcode.DLOAD_3 /* 41 */:
                case Opcode.ALOAD_0 /* 42 */:
                case Opcode.ALOAD_1 /* 43 */:
                case Opcode.ALOAD_2 /* 44 */:
                case 45:
                case 46:
                case 47:
                default:
                    return false;
            }
        }
        return true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1NumericString createPrimitive(byte[] bArr) {
        return new DERNumericString(bArr, false);
    }
}