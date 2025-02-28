package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;
import javassist.bytecode.Opcode;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ASN1OutputStream.class */
public class ASN1OutputStream {

    /* renamed from: os */
    private OutputStream f9os;

    public static ASN1OutputStream create(OutputStream outputStream) {
        return new ASN1OutputStream(outputStream);
    }

    public static ASN1OutputStream create(OutputStream outputStream, String str) {
        return str.equals(ASN1Encoding.DER) ? new DEROutputStream(outputStream) : str.equals(ASN1Encoding.f8DL) ? new DLOutputStream(outputStream) : new ASN1OutputStream(outputStream);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1OutputStream(OutputStream outputStream) {
        this.f9os = outputStream;
    }

    public void close() throws IOException {
        this.f9os.close();
    }

    public void flush() throws IOException {
        this.f9os.flush();
    }

    public final void writeObject(ASN1Encodable aSN1Encodable) throws IOException {
        if (null == aSN1Encodable) {
            throw new IOException("null object detected");
        }
        writePrimitive(aSN1Encodable.toASN1Primitive(), true);
        flushInternal();
    }

    public final void writeObject(ASN1Primitive aSN1Primitive) throws IOException {
        if (null == aSN1Primitive) {
            throw new IOException("null object detected");
        }
        writePrimitive(aSN1Primitive, true);
        flushInternal();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void flushInternal() throws IOException {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DEROutputStream getDERSubStream() {
        return new DEROutputStream(this.f9os);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DLOutputStream getDLSubStream() {
        return new DLOutputStream(this.f9os);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final void writeDL(int i) throws IOException {
        if (i < 128) {
            write(i);
            return;
        }
        byte[] bArr = new byte[5];
        int length = bArr.length;
        do {
            length--;
            bArr[length] = (byte) i;
            i >>>= 8;
        } while (i != 0);
        int length2 = bArr.length - length;
        int i2 = length - 1;
        bArr[i2] = (byte) (128 | length2);
        write(bArr, i2, length2 + 1);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final void write(int i) throws IOException {
        this.f9os.write(i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final void write(byte[] bArr, int i, int i2) throws IOException {
        this.f9os.write(bArr, i, i2);
    }

    void writeElements(ASN1Encodable[] aSN1EncodableArr) throws IOException {
        for (ASN1Encodable aSN1Encodable : aSN1EncodableArr) {
            aSN1Encodable.toASN1Primitive().encode(this, true);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final void writeEncodingDL(boolean z, int i, byte b) throws IOException {
        writeIdentifier(z, i);
        writeDL(1);
        write(b);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final void writeEncodingDL(boolean z, int i, byte[] bArr) throws IOException {
        writeIdentifier(z, i);
        writeDL(bArr.length);
        write(bArr, 0, bArr.length);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final void writeEncodingDL(boolean z, int i, byte[] bArr, int i2, int i3) throws IOException {
        writeIdentifier(z, i);
        writeDL(i3);
        write(bArr, i2, i3);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final void writeEncodingDL(boolean z, int i, byte b, byte[] bArr, int i2, int i3) throws IOException {
        writeIdentifier(z, i);
        writeDL(1 + i3);
        write(b);
        write(bArr, i2, i3);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final void writeEncodingDL(boolean z, int i, byte[] bArr, int i2, int i3, byte b) throws IOException {
        writeIdentifier(z, i);
        writeDL(i3 + 1);
        write(bArr, i2, i3);
        write(b);
    }

    final void writeEncodingDL(boolean z, int i, int i2, byte[] bArr) throws IOException {
        writeIdentifier(z, i, i2);
        writeDL(bArr.length);
        write(bArr, 0, bArr.length);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final void writeEncodingIL(boolean z, int i, ASN1Encodable[] aSN1EncodableArr) throws IOException {
        writeIdentifier(z, i);
        write(128);
        writeElements(aSN1EncodableArr);
        write(0);
        write(0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final void writeIdentifier(boolean z, int i) throws IOException {
        if (z) {
            write(i);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final void writeIdentifier(boolean z, int i, int i2) throws IOException {
        if (z) {
            if (i2 < 31) {
                write(i | i2);
                return;
            }
            byte[] bArr = new byte[6];
            int length = bArr.length - 1;
            bArr[length] = (byte) (i2 & Opcode.LAND);
            while (i2 > 127) {
                i2 >>>= 7;
                length--;
                bArr[length] = (byte) ((i2 & Opcode.LAND) | 128);
            }
            int i3 = length - 1;
            bArr[i3] = (byte) (i | 31);
            write(bArr, i3, bArr.length - i3);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void writePrimitive(ASN1Primitive aSN1Primitive, boolean z) throws IOException {
        aSN1Primitive.encode(this, z);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void writePrimitives(ASN1Primitive[] aSN1PrimitiveArr) throws IOException {
        for (ASN1Primitive aSN1Primitive : aSN1PrimitiveArr) {
            aSN1Primitive.encode(this, true);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getLengthOfDL(int i) {
        if (i < 128) {
            return 1;
        }
        int i2 = 2;
        while (true) {
            int i3 = i >>> 8;
            i = i3;
            if (i3 == 0) {
                return i2;
            }
            i2++;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getLengthOfEncodingDL(boolean z, int i) {
        return (z ? 1 : 0) + getLengthOfDL(i) + i;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getLengthOfIdentifier(int i) {
        if (i < 31) {
            return 1;
        }
        int i2 = 2;
        while (true) {
            int i3 = i >>> 7;
            i = i3;
            if (i3 == 0) {
                return i2;
            }
            i2++;
        }
    }
}