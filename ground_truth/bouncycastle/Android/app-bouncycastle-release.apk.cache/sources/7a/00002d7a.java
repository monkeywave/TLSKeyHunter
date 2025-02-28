package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/* loaded from: classes2.dex */
public final class ServerName {
    private final byte[] nameData;
    private final short nameType;

    public ServerName(short s, byte[] bArr) {
        if (!TlsUtils.isValidUint8(s)) {
            throw new IllegalArgumentException("'nameType' must be from 0 to 255");
        }
        if (bArr == null) {
            throw new NullPointerException("'nameData' cannot be null");
        }
        if (bArr.length < 1 || !TlsUtils.isValidUint16(bArr.length)) {
            throw new IllegalArgumentException("'nameData' must have length from 1 to 65535");
        }
        this.nameType = s;
        this.nameData = bArr;
    }

    public static ServerName parse(InputStream inputStream) throws IOException {
        return new ServerName(TlsUtils.readUint8(inputStream), TlsUtils.readOpaque16(inputStream, 1));
    }

    public void encode(OutputStream outputStream) throws IOException {
        TlsUtils.writeUint8(this.nameType, outputStream);
        TlsUtils.writeOpaque16(this.nameData, outputStream);
    }

    public byte[] getNameData() {
        return this.nameData;
    }

    public short getNameType() {
        return this.nameType;
    }
}