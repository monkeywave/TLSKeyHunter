package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;

/* loaded from: classes.dex */
public class DLBitStringParser implements ASN1BitStringParser {
    private int padBits = 0;
    private final DefiniteLengthInputStream stream;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DLBitStringParser(DefiniteLengthInputStream definiteLengthInputStream) {
        this.stream = definiteLengthInputStream;
    }

    private InputStream getBitStream(boolean z) throws IOException {
        int remaining = this.stream.getRemaining();
        if (remaining >= 1) {
            int read = this.stream.read();
            this.padBits = read;
            if (read > 0) {
                if (remaining < 2) {
                    throw new IllegalStateException("zero length data with non-zero pad bits");
                }
                if (read > 7) {
                    throw new IllegalStateException("pad bits cannot be greater than 7 or less than 0");
                }
                if (z) {
                    throw new IOException("expected octet-aligned bitstring, but found padBits: " + this.padBits);
                }
            }
            return this.stream;
        }
        throw new IllegalStateException("content octets cannot be empty");
    }

    @Override // org.bouncycastle.asn1.ASN1BitStringParser
    public InputStream getBitStream() throws IOException {
        return getBitStream(false);
    }

    @Override // org.bouncycastle.asn1.InMemoryRepresentable
    public ASN1Primitive getLoadedObject() throws IOException {
        return ASN1BitString.createPrimitive(this.stream.toByteArray());
    }

    @Override // org.bouncycastle.asn1.ASN1BitStringParser
    public InputStream getOctetStream() throws IOException {
        return getBitStream(true);
    }

    @Override // org.bouncycastle.asn1.ASN1BitStringParser
    public int getPadBits() {
        return this.padBits;
    }

    @Override // org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        try {
            return getLoadedObject();
        } catch (IOException e) {
            throw new ASN1ParsingException("IOException converting stream to byte array: " + e.getMessage(), e);
        }
    }
}