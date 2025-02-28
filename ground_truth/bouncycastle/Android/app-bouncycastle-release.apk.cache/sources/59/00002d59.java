package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/* loaded from: classes2.dex */
public class KeyShareEntry {
    protected final byte[] keyExchange;
    protected final int namedGroup;

    public KeyShareEntry(int i, byte[] bArr) {
        if (!TlsUtils.isValidUint16(i)) {
            throw new IllegalArgumentException("'namedGroup' should be a uint16");
        }
        if (bArr == null) {
            throw new NullPointerException("'keyExchange' cannot be null");
        }
        if (!checkKeyExchangeLength(bArr.length)) {
            throw new IllegalArgumentException("'keyExchange' must have length from 1 to (2^16 - 1)");
        }
        this.namedGroup = i;
        this.keyExchange = bArr;
    }

    private static boolean checkKeyExchangeLength(int i) {
        return i > 0 && i < 65536;
    }

    public static KeyShareEntry parse(InputStream inputStream) throws IOException {
        return new KeyShareEntry(TlsUtils.readUint16(inputStream), TlsUtils.readOpaque16(inputStream, 1));
    }

    public void encode(OutputStream outputStream) throws IOException {
        TlsUtils.writeUint16(getNamedGroup(), outputStream);
        TlsUtils.writeOpaque16(getKeyExchange(), outputStream);
    }

    public byte[] getKeyExchange() {
        return this.keyExchange;
    }

    public int getNamedGroup() {
        return this.namedGroup;
    }
}