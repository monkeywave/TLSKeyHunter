package org.bouncycastle.asn1;

import java.io.IOException;
import javassist.bytecode.Opcode;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ASN1PrintableString.class */
public abstract class ASN1PrintableString extends ASN1Primitive implements ASN1String {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1PrintableString.class, 19) { // from class: org.bouncycastle.asn1.ASN1PrintableString.1
        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // org.bouncycastle.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString dEROctetString) {
            return ASN1PrintableString.createPrimitive(dEROctetString.getOctets());
        }
    };
    final byte[] contents;

    public static ASN1PrintableString getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1PrintableString)) {
            return (ASN1PrintableString) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive aSN1Primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (aSN1Primitive instanceof ASN1PrintableString) {
                return (ASN1PrintableString) aSN1Primitive;
            }
        }
        if (obj instanceof byte[]) {
            try {
                return (ASN1PrintableString) TYPE.fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1PrintableString getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return (ASN1PrintableString) TYPE.getContextInstance(aSN1TaggedObject, z);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1PrintableString(String str, boolean z) {
        if (z && !isPrintableString(str)) {
            throw new IllegalArgumentException("string contains illegal characters");
        }
        this.contents = Strings.toByteArray(str);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1PrintableString(byte[] bArr, boolean z) {
        this.contents = z ? Arrays.clone(bArr) : bArr;
    }

    @Override // org.bouncycastle.asn1.ASN1String
    public final String getString() {
        return Strings.fromByteArray(this.contents);
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
        aSN1OutputStream.writeEncodingDL(z, 19, this.contents);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public final boolean asn1Equals(ASN1Primitive aSN1Primitive) {
        if (aSN1Primitive instanceof ASN1PrintableString) {
            return Arrays.areEqual(this.contents, ((ASN1PrintableString) aSN1Primitive).contents);
        }
        return false;
    }

    @Override // org.bouncycastle.asn1.ASN1Primitive, org.bouncycastle.asn1.ASN1Object
    public final int hashCode() {
        return Arrays.hashCode(this.contents);
    }

    public String toString() {
        return getString();
    }

    public static boolean isPrintableString(String str) {
        for (int length = str.length() - 1; length >= 0; length--) {
            char charAt = str.charAt(length);
            if (charAt > 127) {
                return false;
            }
            if (('a' > charAt || charAt > 'z') && (('A' > charAt || charAt > 'Z') && ('0' > charAt || charAt > '9'))) {
                switch (charAt) {
                    case ' ':
                    case Opcode.DLOAD_1 /* 39 */:
                    case '(':
                    case Opcode.DLOAD_3 /* 41 */:
                    case Opcode.ALOAD_1 /* 43 */:
                    case Opcode.ALOAD_2 /* 44 */:
                    case '-':
                    case '.':
                    case '/':
                    case Opcode.ASTORE /* 58 */:
                    case Opcode.ISTORE_2 /* 61 */:
                    case '?':
                        break;
                    case Opcode.LLOAD_3 /* 33 */:
                    case Opcode.FLOAD_0 /* 34 */:
                    case '#':
                    case Opcode.FLOAD_2 /* 36 */:
                    case Opcode.FLOAD_3 /* 37 */:
                    case Opcode.DLOAD_0 /* 38 */:
                    case Opcode.ALOAD_0 /* 42 */:
                    case '0':
                    case '1':
                    case '2':
                    case '3':
                    case '4':
                    case '5':
                    case '6':
                    case '7':
                    case '8':
                    case '9':
                    case Opcode.ISTORE_0 /* 59 */:
                    case '<':
                    case Opcode.ISTORE_3 /* 62 */:
                    default:
                        return false;
                }
            }
        }
        return true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1PrintableString createPrimitive(byte[] bArr) {
        return new DERPrintableString(bArr, false);
    }
}