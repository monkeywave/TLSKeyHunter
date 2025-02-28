package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Hashtable;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.p019io.TeeInputStream;

/* loaded from: classes2.dex */
public class ClientHello {
    private final int bindersSize;
    private final int[] cipherSuites;
    private final byte[] cookie;
    private final Hashtable extensions;
    private final byte[] random;
    private final byte[] sessionID;
    private final ProtocolVersion version;

    public ClientHello(ProtocolVersion protocolVersion, byte[] bArr, byte[] bArr2, byte[] bArr3, int[] iArr, Hashtable hashtable, int i) {
        this.version = protocolVersion;
        this.random = bArr;
        this.sessionID = bArr2;
        this.cookie = bArr3;
        this.cipherSuites = iArr;
        this.extensions = hashtable;
        this.bindersSize = i;
    }

    private static ClientHello implParse(ByteArrayInputStream byteArrayInputStream, OutputStream outputStream) throws IOException {
        byte[] bArr;
        Hashtable hashtable;
        InputStream teeInputStream = outputStream != null ? new TeeInputStream(byteArrayInputStream, outputStream) : byteArrayInputStream;
        ProtocolVersion readVersion = TlsUtils.readVersion(teeInputStream);
        byte[] readFully = TlsUtils.readFully(32, teeInputStream);
        byte[] readOpaque8 = TlsUtils.readOpaque8(teeInputStream, 0, 32);
        if (outputStream != null) {
            bArr = TlsUtils.readOpaque8(byteArrayInputStream, 0, ProtocolVersion.DTLSv12.isEqualOrEarlierVersionOf(readVersion) ? 255 : 32);
        } else {
            bArr = null;
        }
        int readUint16 = TlsUtils.readUint16(teeInputStream);
        if (readUint16 < 2 || (readUint16 & 1) != 0 || byteArrayInputStream.available() < readUint16) {
            throw new TlsFatalAlert((short) 50);
        }
        int[] readUint16Array = TlsUtils.readUint16Array(readUint16 / 2, teeInputStream);
        if (Arrays.contains(TlsUtils.readUint8ArrayWithUint8Length(teeInputStream, 1), (short) 0)) {
            if (byteArrayInputStream.available() > 0) {
                byte[] readOpaque16 = TlsUtils.readOpaque16(teeInputStream);
                TlsProtocol.assertEmpty(byteArrayInputStream);
                hashtable = TlsProtocol.readExtensionsDataClientHello(readOpaque16);
            } else {
                hashtable = null;
            }
            return new ClientHello(readVersion, readFully, readOpaque8, bArr, readUint16Array, hashtable, -1);
        }
        throw new TlsFatalAlert((short) 40);
    }

    public static ClientHello parse(ByteArrayInputStream byteArrayInputStream, OutputStream outputStream) throws TlsFatalAlert {
        try {
            return implParse(byteArrayInputStream, outputStream);
        } catch (TlsFatalAlert e) {
            throw e;
        } catch (IOException e2) {
            throw new TlsFatalAlert((short) 50, (Throwable) e2);
        }
    }

    public void encode(TlsContext tlsContext, OutputStream outputStream) throws IOException {
        if (this.bindersSize < 0) {
            throw new TlsFatalAlert((short) 80);
        }
        TlsUtils.writeVersion(this.version, outputStream);
        outputStream.write(this.random);
        TlsUtils.writeOpaque8(this.sessionID, outputStream);
        byte[] bArr = this.cookie;
        if (bArr != null) {
            TlsUtils.writeOpaque8(bArr, outputStream);
        }
        TlsUtils.writeUint16ArrayWithUint16Length(this.cipherSuites, outputStream);
        TlsUtils.writeUint8ArrayWithUint8Length(new short[]{0}, outputStream);
        TlsProtocol.writeExtensions(outputStream, this.extensions, this.bindersSize);
    }

    public int getBindersSize() {
        return this.bindersSize;
    }

    public int[] getCipherSuites() {
        return this.cipherSuites;
    }

    public ProtocolVersion getClientVersion() {
        return this.version;
    }

    public byte[] getCookie() {
        return this.cookie;
    }

    public Hashtable getExtensions() {
        return this.extensions;
    }

    public byte[] getRandom() {
        return this.random;
    }

    public byte[] getSessionID() {
        return this.sessionID;
    }

    public ProtocolVersion getVersion() {
        return this.version;
    }
}