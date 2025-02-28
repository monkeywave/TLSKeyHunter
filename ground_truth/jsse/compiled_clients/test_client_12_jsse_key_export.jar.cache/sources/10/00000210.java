package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/BERGenerator.class */
public abstract class BERGenerator extends ASN1Generator {
    private boolean _tagged;
    private boolean _isExplicit;
    private int _tagNo;

    /* JADX INFO: Access modifiers changed from: protected */
    public BERGenerator(OutputStream outputStream) {
        super(outputStream);
        this._tagged = false;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public BERGenerator(OutputStream outputStream, int i, boolean z) {
        super(outputStream);
        this._tagged = false;
        this._tagged = true;
        this._isExplicit = z;
        this._tagNo = i;
    }

    @Override // org.bouncycastle.asn1.ASN1Generator
    public OutputStream getRawOutputStream() {
        return this._out;
    }

    private void writeHdr(int i) throws IOException {
        this._out.write(i);
        this._out.write(128);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void writeBERHeader(int i) throws IOException {
        if (!this._tagged) {
            writeHdr(i);
            return;
        }
        int i2 = this._tagNo | 128;
        if (this._isExplicit) {
            writeHdr(i2 | 32);
            writeHdr(i);
        } else if ((i & 32) != 0) {
            writeHdr(i2 | 32);
        } else {
            writeHdr(i2);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void writeBEREnd() throws IOException {
        this._out.write(0);
        this._out.write(0);
        if (this._tagged && this._isExplicit) {
            this._out.write(0);
            this._out.write(0);
        }
    }
}