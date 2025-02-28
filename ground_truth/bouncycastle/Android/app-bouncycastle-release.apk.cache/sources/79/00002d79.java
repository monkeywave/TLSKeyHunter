package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Hashtable;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class ServerHello {
    private static final byte[] HELLO_RETRY_REQUEST_MAGIC = {-49, 33, -83, 116, -27, -102, 97, 17, -66, 29, -116, 2, 30, 101, -72, -111, -62, -94, 17, 22, 122, -69, -116, 94, 7, -98, 9, -30, -56, -88, 51, -100};
    private final int cipherSuite;
    private final Hashtable extensions;
    private final byte[] random;
    private final byte[] sessionID;
    private final ProtocolVersion version;

    public ServerHello(ProtocolVersion protocolVersion, byte[] bArr, byte[] bArr2, int i, Hashtable hashtable) {
        this.version = protocolVersion;
        this.random = bArr;
        this.sessionID = bArr2;
        this.cipherSuite = i;
        this.extensions = hashtable;
    }

    public ServerHello(byte[] bArr, int i, Hashtable hashtable) {
        this(ProtocolVersion.TLSv12, Arrays.clone(HELLO_RETRY_REQUEST_MAGIC), bArr, i, hashtable);
    }

    public static ServerHello parse(ByteArrayInputStream byteArrayInputStream) throws IOException {
        ProtocolVersion readVersion = TlsUtils.readVersion(byteArrayInputStream);
        byte[] readFully = TlsUtils.readFully(32, byteArrayInputStream);
        byte[] readOpaque8 = TlsUtils.readOpaque8(byteArrayInputStream, 0, 32);
        int readUint16 = TlsUtils.readUint16(byteArrayInputStream);
        if (TlsUtils.readUint8(byteArrayInputStream) == 0) {
            return new ServerHello(readVersion, readFully, readOpaque8, readUint16, TlsProtocol.readExtensions(byteArrayInputStream));
        }
        throw new TlsFatalAlert((short) 47);
    }

    public void encode(TlsContext tlsContext, OutputStream outputStream) throws IOException {
        TlsUtils.writeVersion(this.version, outputStream);
        outputStream.write(this.random);
        TlsUtils.writeOpaque8(this.sessionID, outputStream);
        TlsUtils.writeUint16(this.cipherSuite, outputStream);
        TlsUtils.writeUint8((short) 0, outputStream);
        TlsProtocol.writeExtensions(outputStream, this.extensions);
    }

    public int getCipherSuite() {
        return this.cipherSuite;
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

    public boolean isHelloRetryRequest() {
        return Arrays.areEqual(HELLO_RETRY_REQUEST_MAGIC, this.random);
    }
}