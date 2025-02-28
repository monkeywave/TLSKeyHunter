package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.tls.CipherSuite;

/* loaded from: classes.dex */
public abstract class DERGenerator extends ASN1Generator {
    private boolean _isExplicit;
    private int _tagNo;
    private boolean _tagged;

    /* JADX INFO: Access modifiers changed from: protected */
    public DERGenerator(OutputStream outputStream) {
        super(outputStream);
        this._tagged = false;
    }

    public DERGenerator(OutputStream outputStream, int i, boolean z) {
        super(outputStream);
        this._tagged = true;
        this._isExplicit = z;
        this._tagNo = i;
    }

    private void writeLength(OutputStream outputStream, int i) throws IOException {
        if (i <= 127) {
            outputStream.write((byte) i);
            return;
        }
        int i2 = i;
        int i3 = 1;
        while (true) {
            i2 >>>= 8;
            if (i2 == 0) {
                break;
            }
            i3++;
        }
        outputStream.write((byte) (i3 | 128));
        for (int i4 = (i3 - 1) * 8; i4 >= 0; i4 -= 8) {
            outputStream.write((byte) (i >> i4));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void writeDEREncoded(int i, byte[] bArr) throws IOException {
        if (!this._tagged) {
            writeDEREncoded(this._out, i, bArr);
            return;
        }
        int i2 = this._tagNo;
        int i3 = i2 | 128;
        if (this._isExplicit) {
            int i4 = i2 | CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256;
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            writeDEREncoded(byteArrayOutputStream, i, bArr);
            writeDEREncoded(this._out, i4, byteArrayOutputStream.toByteArray());
        } else if ((i & 32) != 0) {
            writeDEREncoded(this._out, i2 | CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, bArr);
        } else {
            writeDEREncoded(this._out, i3, bArr);
        }
    }

    void writeDEREncoded(OutputStream outputStream, int i, byte[] bArr) throws IOException {
        outputStream.write(i);
        writeLength(outputStream, bArr.length);
        outputStream.write(bArr);
    }
}