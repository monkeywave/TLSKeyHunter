package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class URLAndHash {
    protected byte[] sha1Hash;
    protected String url;

    public URLAndHash(String str, byte[] bArr) {
        if (TlsUtils.isNullOrEmpty(str) || str.length() >= 65536) {
            throw new IllegalArgumentException("'url' must have length from 1 to (2^16 - 1)");
        }
        if (bArr != null && bArr.length != 20) {
            throw new IllegalArgumentException("'sha1Hash' must have length == 20, if present");
        }
        this.url = str;
        this.sha1Hash = bArr;
    }

    public static URLAndHash parse(TlsContext tlsContext, InputStream inputStream) throws IOException {
        byte[] bArr;
        String fromByteArray = Strings.fromByteArray(TlsUtils.readOpaque16(inputStream, 1));
        short readUint8 = TlsUtils.readUint8(inputStream);
        if (readUint8 != 0) {
            if (readUint8 != 1) {
                throw new TlsFatalAlert((short) 47);
            }
            bArr = TlsUtils.readFully(20, inputStream);
        } else if (TlsUtils.isTLSv12(tlsContext)) {
            throw new TlsFatalAlert((short) 47);
        } else {
            bArr = null;
        }
        return new URLAndHash(fromByteArray, bArr);
    }

    public void encode(OutputStream outputStream) throws IOException {
        TlsUtils.writeOpaque16(Strings.toByteArray(this.url), outputStream);
        if (this.sha1Hash == null) {
            TlsUtils.writeUint8(0, outputStream);
            return;
        }
        TlsUtils.writeUint8(1, outputStream);
        outputStream.write(this.sha1Hash);
    }

    public byte[] getSHA1Hash() {
        return this.sha1Hash;
    }

    public String getURL() {
        return this.url;
    }
}