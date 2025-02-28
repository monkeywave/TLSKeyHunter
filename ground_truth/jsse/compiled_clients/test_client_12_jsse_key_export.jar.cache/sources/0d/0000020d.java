package org.bouncycastle.asn1;

import java.io.IOException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/BERBitString.class */
public class BERBitString extends ASN1BitString {
    private static final int DEFAULT_SEGMENT_LIMIT = 1000;
    private final int segmentLimit;
    private final ASN1BitString[] elements;

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] flattenBitStrings(ASN1BitString[] aSN1BitStringArr) {
        int length = aSN1BitStringArr.length;
        switch (length) {
            case 0:
                return new byte[]{0};
            case 1:
                return aSN1BitStringArr[0].contents;
            default:
                int i = length - 1;
                int i2 = 0;
                for (int i3 = 0; i3 < i; i3++) {
                    byte[] bArr = aSN1BitStringArr[i3].contents;
                    if (bArr[0] != 0) {
                        throw new IllegalArgumentException("only the last nested bitstring can have padding");
                    }
                    i2 += bArr.length - 1;
                }
                byte[] bArr2 = aSN1BitStringArr[i].contents;
                byte b = bArr2[0];
                byte[] bArr3 = new byte[i2 + bArr2.length];
                bArr3[0] = b;
                int i4 = 1;
                for (ASN1BitString aSN1BitString : aSN1BitStringArr) {
                    byte[] bArr4 = aSN1BitString.contents;
                    int length2 = bArr4.length - 1;
                    System.arraycopy(bArr4, 1, bArr3, i4, length2);
                    i4 += length2;
                }
                return bArr3;
        }
    }

    public BERBitString(byte[] bArr) {
        this(bArr, 0);
    }

    public BERBitString(byte b, int i) {
        super(b, i);
        this.elements = null;
        this.segmentLimit = DEFAULT_SEGMENT_LIMIT;
    }

    public BERBitString(byte[] bArr, int i) {
        this(bArr, i, DEFAULT_SEGMENT_LIMIT);
    }

    public BERBitString(byte[] bArr, int i, int i2) {
        super(bArr, i);
        this.elements = null;
        this.segmentLimit = i2;
    }

    public BERBitString(ASN1Encodable aSN1Encodable) throws IOException {
        this(aSN1Encodable.toASN1Primitive().getEncoded(ASN1Encoding.DER), 0);
    }

    public BERBitString(ASN1BitString[] aSN1BitStringArr) {
        this(aSN1BitStringArr, (int) DEFAULT_SEGMENT_LIMIT);
    }

    public BERBitString(ASN1BitString[] aSN1BitStringArr, int i) {
        super(flattenBitStrings(aSN1BitStringArr), false);
        this.elements = aSN1BitStringArr;
        this.segmentLimit = i;
    }

    BERBitString(byte[] bArr, boolean z) {
        super(bArr, z);
        this.elements = null;
        this.segmentLimit = DEFAULT_SEGMENT_LIMIT;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return null != this.elements || this.contents.length > this.segmentLimit;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public int encodedLength(boolean z) throws IOException {
        if (encodeConstructed()) {
            int i = z ? 4 : 3;
            if (null != this.elements) {
                for (int i2 = 0; i2 < this.elements.length; i2++) {
                    i += this.elements[i2].encodedLength(true);
                }
            } else if (this.contents.length >= 2) {
                int length = (this.contents.length - 2) / (this.segmentLimit - 1);
                i = i + (length * DLBitString.encodedLength(true, this.segmentLimit)) + DLBitString.encodedLength(true, this.contents.length - (length * (this.segmentLimit - 1)));
            }
            return i;
        }
        return DLBitString.encodedLength(z, this.contents.length);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public void encode(ASN1OutputStream aSN1OutputStream, boolean z) throws IOException {
        if (!encodeConstructed()) {
            DLBitString.encode(aSN1OutputStream, z, this.contents, 0, this.contents.length);
            return;
        }
        aSN1OutputStream.writeIdentifier(z, 35);
        aSN1OutputStream.write(128);
        if (null != this.elements) {
            aSN1OutputStream.writePrimitives(this.elements);
        } else if (this.contents.length >= 2) {
            byte b = this.contents[0];
            int length = this.contents.length;
            int i = length - 1;
            int i2 = this.segmentLimit - 1;
            while (i > i2) {
                DLBitString.encode(aSN1OutputStream, true, (byte) 0, this.contents, length - i, i2);
                i -= i2;
            }
            DLBitString.encode(aSN1OutputStream, true, b, this.contents, length - i, i);
        }
        aSN1OutputStream.write(0);
        aSN1OutputStream.write(0);
    }
}