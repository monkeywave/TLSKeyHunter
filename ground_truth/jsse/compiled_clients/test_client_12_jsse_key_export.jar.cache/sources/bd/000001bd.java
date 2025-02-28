package org.bouncycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ASN1BitString.class */
public abstract class ASN1BitString extends ASN1Primitive implements ASN1String, ASN1BitStringParser {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1BitString.class, 3) { // from class: org.bouncycastle.asn1.ASN1BitString.1
        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // org.bouncycastle.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString dEROctetString) {
            return ASN1BitString.createPrimitive(dEROctetString.getOctets());
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // org.bouncycastle.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitConstructed(ASN1Sequence aSN1Sequence) {
            return aSN1Sequence.toASN1BitString();
        }
    };
    private static final char[] table = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    final byte[] contents;

    public static ASN1BitString getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1BitString)) {
            return (ASN1BitString) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive aSN1Primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (aSN1Primitive instanceof ASN1BitString) {
                return (ASN1BitString) aSN1Primitive;
            }
        } else if (obj instanceof byte[]) {
            try {
                return (ASN1BitString) TYPE.fromByteArray((byte[]) obj);
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to construct BIT STRING from byte[]: " + e.getMessage());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1BitString getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return (ASN1BitString) TYPE.getContextInstance(aSN1TaggedObject, z);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static int getPadBits(int i) {
        int i2 = 0;
        int i3 = 3;
        while (true) {
            if (i3 < 0) {
                break;
            } else if (i3 != 0) {
                if ((i >> (i3 * 8)) != 0) {
                    i2 = (i >> (i3 * 8)) & GF2Field.MASK;
                    break;
                }
                i3--;
            } else if (i != 0) {
                i2 = i & GF2Field.MASK;
                break;
            } else {
                i3--;
            }
        }
        if (i2 == 0) {
            return 0;
        }
        int i4 = 1;
        while (true) {
            int i5 = i2 << 1;
            i2 = i5;
            if ((i5 & GF2Field.MASK) == 0) {
                return 8 - i4;
            }
            i4++;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static byte[] getBytes(int i) {
        if (i == 0) {
            return new byte[0];
        }
        int i2 = 4;
        for (int i3 = 3; i3 >= 1 && (i & (GF2Field.MASK << (i3 * 8))) == 0; i3--) {
            i2--;
        }
        byte[] bArr = new byte[i2];
        for (int i4 = 0; i4 < i2; i4++) {
            bArr[i4] = (byte) ((i >> (i4 * 8)) & GF2Field.MASK);
        }
        return bArr;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1BitString(byte b, int i) {
        if (i > 7 || i < 0) {
            throw new IllegalArgumentException("pad bits cannot be greater than 7 or less than 0");
        }
        this.contents = new byte[]{(byte) i, b};
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1BitString(byte[] bArr, int i) {
        if (bArr == null) {
            throw new NullPointerException("'data' cannot be null");
        }
        if (bArr.length == 0 && i != 0) {
            throw new IllegalArgumentException("zero length data with non-zero pad bits");
        }
        if (i > 7 || i < 0) {
            throw new IllegalArgumentException("pad bits cannot be greater than 7 or less than 0");
        }
        this.contents = Arrays.prepend(bArr, (byte) i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1BitString(byte[] bArr, boolean z) {
        if (z) {
            if (null == bArr) {
                throw new NullPointerException("'contents' cannot be null");
            }
            if (bArr.length < 1) {
                throw new IllegalArgumentException("'contents' cannot be empty");
            }
            int i = bArr[0] & 255;
            if (i > 0) {
                if (bArr.length < 2) {
                    throw new IllegalArgumentException("zero length data with non-zero pad bits");
                }
                if (i > 7) {
                    throw new IllegalArgumentException("pad bits cannot be greater than 7 or less than 0");
                }
            }
        }
        this.contents = bArr;
    }

    @Override // org.bouncycastle.asn1.ASN1BitStringParser
    public InputStream getBitStream() throws IOException {
        return new ByteArrayInputStream(this.contents, 1, this.contents.length - 1);
    }

    @Override // org.bouncycastle.asn1.ASN1BitStringParser
    public InputStream getOctetStream() throws IOException {
        int i = this.contents[0] & 255;
        if (0 != i) {
            throw new IOException("expected octet-aligned bitstring, but found padBits: " + i);
        }
        return getBitStream();
    }

    public ASN1BitStringParser parser() {
        return this;
    }

    @Override // org.bouncycastle.asn1.ASN1String
    public String getString() {
        try {
            byte[] encoded = getEncoded();
            StringBuffer stringBuffer = new StringBuffer(1 + (encoded.length * 2));
            stringBuffer.append('#');
            for (int i = 0; i != encoded.length; i++) {
                byte b = encoded[i];
                stringBuffer.append(table[(b >>> 4) & 15]);
                stringBuffer.append(table[b & 15]);
            }
            return stringBuffer.toString();
        } catch (IOException e) {
            throw new ASN1ParsingException("Internal error encoding BitString: " + e.getMessage(), e);
        }
    }

    public int intValue() {
        int i = 0;
        int min = Math.min(5, this.contents.length - 1);
        for (int i2 = 1; i2 < min; i2++) {
            i |= (this.contents[i2] & 255) << (8 * (i2 - 1));
        }
        if (1 <= min && min < 5) {
            i |= (((byte) (this.contents[min] & (GF2Field.MASK << (this.contents[0] & 255)))) & 255) << (8 * (min - 1));
        }
        return i;
    }

    public byte[] getOctets() {
        if (this.contents[0] != 0) {
            throw new IllegalStateException("attempt to get non-octet aligned data from BIT STRING");
        }
        return Arrays.copyOfRange(this.contents, 1, this.contents.length);
    }

    public byte[] getBytes() {
        if (this.contents.length == 1) {
            return ASN1OctetString.EMPTY_OCTETS;
        }
        int i = this.contents[0] & 255;
        byte[] copyOfRange = Arrays.copyOfRange(this.contents, 1, this.contents.length);
        int length = copyOfRange.length - 1;
        copyOfRange[length] = (byte) (copyOfRange[length] & ((byte) (GF2Field.MASK << i)));
        return copyOfRange;
    }

    @Override // org.bouncycastle.asn1.ASN1BitStringParser
    public int getPadBits() {
        return this.contents[0] & 255;
    }

    public String toString() {
        return getString();
    }

    @Override // org.bouncycastle.asn1.ASN1Primitive, org.bouncycastle.asn1.ASN1Object
    public int hashCode() {
        if (this.contents.length < 2) {
            return 1;
        }
        int i = this.contents[0] & 255;
        int length = this.contents.length - 1;
        return (Arrays.hashCode(this.contents, 0, length) * 257) ^ ((byte) (this.contents[length] & (GF2Field.MASK << i)));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public boolean asn1Equals(ASN1Primitive aSN1Primitive) {
        if (aSN1Primitive instanceof ASN1BitString) {
            byte[] bArr = this.contents;
            byte[] bArr2 = ((ASN1BitString) aSN1Primitive).contents;
            int length = bArr.length;
            if (bArr2.length != length) {
                return false;
            }
            if (length == 1) {
                return true;
            }
            int i = length - 1;
            for (int i2 = 0; i2 < i; i2++) {
                if (bArr[i2] != bArr2[i2]) {
                    return false;
                }
            }
            int i3 = bArr[0] & 255;
            return ((byte) (bArr[i] & (GF2Field.MASK << i3))) == ((byte) (bArr2[i] & (GF2Field.MASK << i3)));
        }
        return false;
    }

    @Override // org.bouncycastle.asn1.InMemoryRepresentable
    public ASN1Primitive getLoadedObject() {
        return toASN1Primitive();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        return new DERBitString(this.contents, false);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return new DLBitString(this.contents, false);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1BitString createPrimitive(byte[] bArr) {
        int length = bArr.length;
        if (length < 1) {
            throw new IllegalArgumentException("truncated BIT STRING detected");
        }
        int i = bArr[0] & 255;
        if (i > 0) {
            if (i > 7 || length < 2) {
                throw new IllegalArgumentException("invalid pad bits detected");
            }
            byte b = bArr[length - 1];
            if (b != ((byte) (b & (GF2Field.MASK << i)))) {
                return new DLBitString(bArr, false);
            }
        }
        return new DERBitString(bArr, false);
    }
}