package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ConstructedOctetStream.class */
public class ConstructedOctetStream extends InputStream {
    private final ASN1StreamParser _parser;
    private boolean _first = true;
    private InputStream _currentStream;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ConstructedOctetStream(ASN1StreamParser aSN1StreamParser) {
        this._parser = aSN1StreamParser;
    }

    @Override // java.io.InputStream
    public int read(byte[] bArr, int i, int i2) throws IOException {
        ASN1OctetStringParser nextParser;
        if (this._currentStream == null) {
            if (!this._first || (nextParser = getNextParser()) == null) {
                return -1;
            }
            this._first = false;
            this._currentStream = nextParser.getOctetStream();
        }
        int i3 = 0;
        while (true) {
            int read = this._currentStream.read(bArr, i + i3, i2 - i3);
            if (read >= 0) {
                i3 += read;
                if (i3 == i2) {
                    return i3;
                }
            } else {
                ASN1OctetStringParser nextParser2 = getNextParser();
                if (nextParser2 == null) {
                    this._currentStream = null;
                    if (i3 < 1) {
                        return -1;
                    }
                    return i3;
                }
                this._currentStream = nextParser2.getOctetStream();
            }
        }
    }

    @Override // java.io.InputStream
    public int read() throws IOException {
        ASN1OctetStringParser nextParser;
        if (this._currentStream == null) {
            if (!this._first || (nextParser = getNextParser()) == null) {
                return -1;
            }
            this._first = false;
            this._currentStream = nextParser.getOctetStream();
        }
        while (true) {
            int read = this._currentStream.read();
            if (read >= 0) {
                return read;
            }
            ASN1OctetStringParser nextParser2 = getNextParser();
            if (nextParser2 == null) {
                this._currentStream = null;
                return -1;
            }
            this._currentStream = nextParser2.getOctetStream();
        }
    }

    private ASN1OctetStringParser getNextParser() throws IOException {
        ASN1Encodable readObject = this._parser.readObject();
        if (readObject == null) {
            return null;
        }
        if (readObject instanceof ASN1OctetStringParser) {
            return (ASN1OctetStringParser) readObject;
        }
        throw new IOException("unknown object encountered: " + readObject.getClass());
    }
}