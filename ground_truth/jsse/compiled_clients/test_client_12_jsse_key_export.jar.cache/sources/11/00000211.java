package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;
import java.util.NoSuchElementException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/BEROctetString.class */
public class BEROctetString extends ASN1OctetString {
    private static final int DEFAULT_SEGMENT_LIMIT = 1000;
    private final int segmentLimit;
    private final ASN1OctetString[] elements;

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] flattenOctetStrings(ASN1OctetString[] aSN1OctetStringArr) {
        switch (aSN1OctetStringArr.length) {
            case 0:
                return EMPTY_OCTETS;
            case 1:
                return aSN1OctetStringArr[0].string;
            default:
                int i = 0;
                for (ASN1OctetString aSN1OctetString : aSN1OctetStringArr) {
                    i += aSN1OctetString.string.length;
                }
                byte[] bArr = new byte[i];
                int i2 = 0;
                for (ASN1OctetString aSN1OctetString2 : aSN1OctetStringArr) {
                    byte[] bArr2 = aSN1OctetString2.string;
                    System.arraycopy(bArr2, 0, bArr, i2, bArr2.length);
                    i2 += bArr2.length;
                }
                return bArr;
        }
    }

    public BEROctetString(byte[] bArr) {
        this(bArr, (int) DEFAULT_SEGMENT_LIMIT);
    }

    public BEROctetString(ASN1OctetString[] aSN1OctetStringArr) {
        this(aSN1OctetStringArr, (int) DEFAULT_SEGMENT_LIMIT);
    }

    public BEROctetString(byte[] bArr, int i) {
        this(bArr, null, i);
    }

    public BEROctetString(ASN1OctetString[] aSN1OctetStringArr, int i) {
        this(flattenOctetStrings(aSN1OctetStringArr), aSN1OctetStringArr, i);
    }

    private BEROctetString(byte[] bArr, ASN1OctetString[] aSN1OctetStringArr, int i) {
        super(bArr);
        this.elements = aSN1OctetStringArr;
        this.segmentLimit = i;
    }

    public Enumeration getObjects() {
        return this.elements == null ? new Enumeration() { // from class: org.bouncycastle.asn1.BEROctetString.1
            int pos = 0;

            @Override // java.util.Enumeration
            public boolean hasMoreElements() {
                return this.pos < BEROctetString.this.string.length;
            }

            @Override // java.util.Enumeration
            public Object nextElement() {
                if (this.pos < BEROctetString.this.string.length) {
                    int min = Math.min(BEROctetString.this.string.length - this.pos, BEROctetString.this.segmentLimit);
                    byte[] bArr = new byte[min];
                    System.arraycopy(BEROctetString.this.string, this.pos, bArr, 0, min);
                    this.pos += min;
                    return new DEROctetString(bArr);
                }
                throw new NoSuchElementException();
            }
        } : new Enumeration() { // from class: org.bouncycastle.asn1.BEROctetString.2
            int counter = 0;

            @Override // java.util.Enumeration
            public boolean hasMoreElements() {
                return this.counter < BEROctetString.this.elements.length;
            }

            @Override // java.util.Enumeration
            public Object nextElement() {
                if (this.counter < BEROctetString.this.elements.length) {
                    ASN1OctetString[] aSN1OctetStringArr = BEROctetString.this.elements;
                    int i = this.counter;
                    this.counter = i + 1;
                    return aSN1OctetStringArr[i];
                }
                throw new NoSuchElementException();
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return null != this.elements || this.string.length > this.segmentLimit;
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
            } else {
                int length = this.string.length / this.segmentLimit;
                i += length * DEROctetString.encodedLength(true, this.segmentLimit);
                int length2 = this.string.length - (length * this.segmentLimit);
                if (length2 > 0) {
                    i += DEROctetString.encodedLength(true, length2);
                }
            }
            return i;
        }
        return DEROctetString.encodedLength(z, this.string.length);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public void encode(ASN1OutputStream aSN1OutputStream, boolean z) throws IOException {
        if (!encodeConstructed()) {
            DEROctetString.encode(aSN1OutputStream, z, this.string, 0, this.string.length);
            return;
        }
        aSN1OutputStream.writeIdentifier(z, 36);
        aSN1OutputStream.write(128);
        if (null == this.elements) {
            int i = 0;
            while (true) {
                int i2 = i;
                if (i2 >= this.string.length) {
                    break;
                }
                int min = Math.min(this.string.length - i2, this.segmentLimit);
                DEROctetString.encode(aSN1OutputStream, true, this.string, i2, min);
                i = i2 + min;
            }
        } else {
            aSN1OutputStream.writePrimitives(this.elements);
        }
        aSN1OutputStream.write(0);
        aSN1OutputStream.write(0);
    }
}