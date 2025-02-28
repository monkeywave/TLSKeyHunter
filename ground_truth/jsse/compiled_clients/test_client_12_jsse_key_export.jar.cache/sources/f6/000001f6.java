package org.bouncycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ASN1StreamParser.class */
public class ASN1StreamParser {
    private final InputStream _in;
    private final int _limit;
    private final byte[][] tmpBuffers;

    public ASN1StreamParser(InputStream inputStream) {
        this(inputStream, StreamUtil.findLimit(inputStream));
    }

    public ASN1StreamParser(byte[] bArr) {
        this(new ByteArrayInputStream(bArr), bArr.length);
    }

    /* JADX WARN: Type inference failed for: r3v1, types: [byte[], byte[][]] */
    public ASN1StreamParser(InputStream inputStream, int i) {
        this(inputStream, i, new byte[11]);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1StreamParser(InputStream inputStream, int i, byte[][] bArr) {
        this._in = inputStream;
        this._limit = i;
        this.tmpBuffers = bArr;
    }

    public ASN1Encodable readObject() throws IOException {
        int read = this._in.read();
        if (read < 0) {
            return null;
        }
        return implParseObject(read);
    }

    ASN1Encodable implParseObject(int i) throws IOException {
        set00Check(false);
        int readTagNumber = ASN1InputStream.readTagNumber(this._in, i);
        int readLength = ASN1InputStream.readLength(this._in, this._limit, readTagNumber == 3 || readTagNumber == 4 || readTagNumber == 16 || readTagNumber == 17 || readTagNumber == 8);
        if (readLength < 0) {
            if (0 == (i & 32)) {
                throw new IOException("indefinite-length primitive encoding encountered");
            }
            ASN1StreamParser aSN1StreamParser = new ASN1StreamParser(new IndefiniteLengthInputStream(this._in, this._limit), this._limit, this.tmpBuffers);
            int i2 = i & 192;
            return 0 != i2 ? 64 == i2 ? new BERApplicationSpecificParser(readTagNumber, aSN1StreamParser) : new BERTaggedObjectParser(i2, readTagNumber, aSN1StreamParser) : aSN1StreamParser.parseImplicitConstructedIL(readTagNumber);
        }
        DefiniteLengthInputStream definiteLengthInputStream = new DefiniteLengthInputStream(this._in, readLength, this._limit);
        if (0 == (i & BERTags.FLAGS)) {
            return parseImplicitPrimitive(readTagNumber, definiteLengthInputStream);
        }
        ASN1StreamParser aSN1StreamParser2 = new ASN1StreamParser(definiteLengthInputStream, definiteLengthInputStream.getLimit(), this.tmpBuffers);
        int i3 = i & 192;
        if (0 != i3) {
            boolean z = (i & 32) != 0;
            return 64 == i3 ? (DLApplicationSpecific) aSN1StreamParser2.loadTaggedDL(i3, readTagNumber, z) : new DLTaggedObjectParser(i3, readTagNumber, z, aSN1StreamParser2);
        }
        return aSN1StreamParser2.parseImplicitConstructedDL(readTagNumber);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1Primitive loadTaggedDL(int i, int i2, boolean z) throws IOException {
        return !z ? ASN1TaggedObject.createPrimitive(i, i2, ((DefiniteLengthInputStream) this._in).toByteArray()) : ASN1TaggedObject.createConstructedDL(i, i2, readVector());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1Primitive loadTaggedIL(int i, int i2) throws IOException {
        return ASN1TaggedObject.createConstructedIL(i, i2, readVector());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1Encodable parseImplicitConstructedDL(int i) throws IOException {
        switch (i) {
            case 3:
                return new BERBitStringParser(this);
            case 4:
                return new BEROctetStringParser(this);
            case 5:
            case 6:
            case 7:
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
            case 15:
            default:
                throw new ASN1Exception("unknown DL object encountered: 0x" + Integer.toHexString(i));
            case 8:
                return new DERExternalParser(this);
            case 16:
                return new DLSequenceParser(this);
            case 17:
                return new DLSetParser(this);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1Encodable parseImplicitConstructedIL(int i) throws IOException {
        switch (i) {
            case 3:
                return new BERBitStringParser(this);
            case 4:
                return new BEROctetStringParser(this);
            case 5:
            case 6:
            case 7:
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
            case 15:
            default:
                throw new ASN1Exception("unknown BER object encountered: 0x" + Integer.toHexString(i));
            case 8:
                return new DERExternalParser(this);
            case 16:
                return new BERSequenceParser(this);
            case 17:
                return new BERSetParser(this);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1Encodable parseImplicitPrimitive(int i) throws IOException {
        return parseImplicitPrimitive(i, (DefiniteLengthInputStream) this._in);
    }

    ASN1Encodable parseImplicitPrimitive(int i, DefiniteLengthInputStream definiteLengthInputStream) throws IOException {
        switch (i) {
            case 3:
                return new DLBitStringParser(definiteLengthInputStream);
            case 4:
                return new DEROctetStringParser(definiteLengthInputStream);
            case 5:
            case 6:
            case 7:
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
            case 15:
            default:
                try {
                    return ASN1InputStream.createPrimitiveDERObject(i, definiteLengthInputStream, this.tmpBuffers);
                } catch (IllegalArgumentException e) {
                    throw new ASN1Exception("corrupted stream detected", e);
                }
            case 8:
                throw new ASN1Exception("externals must use constructed encoding (see X.690 8.18)");
            case 16:
                throw new ASN1Exception("sets must use constructed encoding (see X.690 8.11.1/8.12.1)");
            case 17:
                throw new ASN1Exception("sequences must use constructed encoding (see X.690 8.9.1/8.10.1)");
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1Encodable parseObject(int i) throws IOException {
        if (i < 0 || i > 30) {
            throw new IllegalArgumentException("invalid universal tag number: " + i);
        }
        int read = this._in.read();
        if (read < 0) {
            return null;
        }
        if ((read & (-33)) != i) {
            throw new IOException("unexpected identifier encountered: " + read);
        }
        return implParseObject(read);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1TaggedObjectParser parseTaggedObject() throws IOException {
        int read = this._in.read();
        if (read < 0) {
            return null;
        }
        if (0 == (read & 192)) {
            throw new ASN1Exception("no tagged object found");
        }
        return (ASN1TaggedObjectParser) implParseObject(read);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1EncodableVector readVector() throws IOException {
        int read;
        int read2 = this._in.read();
        if (read2 < 0) {
            return new ASN1EncodableVector(0);
        }
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        do {
            ASN1Encodable implParseObject = implParseObject(read2);
            if (implParseObject instanceof InMemoryRepresentable) {
                aSN1EncodableVector.add(((InMemoryRepresentable) implParseObject).getLoadedObject());
            } else {
                aSN1EncodableVector.add(implParseObject.toASN1Primitive());
            }
            read = this._in.read();
            read2 = read;
        } while (read >= 0);
        return aSN1EncodableVector;
    }

    private void set00Check(boolean z) {
        if (this._in instanceof IndefiniteLengthInputStream) {
            ((IndefiniteLengthInputStream) this._in).setEofOn00(z);
        }
    }
}