package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/* loaded from: classes2.dex */
public class CertificateStatusRequestItemV2 {
    protected Object request;
    protected short statusType;

    public CertificateStatusRequestItemV2(short s, Object obj) {
        if (!isCorrectType(s, obj)) {
            throw new IllegalArgumentException("'request' is not an instance of the correct type");
        }
        this.statusType = s;
        this.request = obj;
    }

    protected static boolean isCorrectType(short s, Object obj) {
        if (s == 1 || s == 2) {
            return obj instanceof OCSPStatusRequest;
        }
        throw new IllegalArgumentException("'statusType' is an unsupported CertificateStatusType");
    }

    public static CertificateStatusRequestItemV2 parse(InputStream inputStream) throws IOException {
        short readUint8 = TlsUtils.readUint8(inputStream);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(TlsUtils.readOpaque16(inputStream));
        if (readUint8 == 1 || readUint8 == 2) {
            OCSPStatusRequest parse = OCSPStatusRequest.parse(byteArrayInputStream);
            TlsProtocol.assertEmpty(byteArrayInputStream);
            return new CertificateStatusRequestItemV2(readUint8, parse);
        }
        throw new TlsFatalAlert((short) 50);
    }

    public void encode(OutputStream outputStream) throws IOException {
        TlsUtils.writeUint8(this.statusType, outputStream);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        short s = this.statusType;
        if (s != 1 && s != 2) {
            throw new TlsFatalAlert((short) 80);
        }
        ((OCSPStatusRequest) this.request).encode(byteArrayOutputStream);
        TlsUtils.writeOpaque16(byteArrayOutputStream.toByteArray(), outputStream);
    }

    public OCSPStatusRequest getOCSPStatusRequest() {
        Object obj = this.request;
        if (obj instanceof OCSPStatusRequest) {
            return (OCSPStatusRequest) obj;
        }
        throw new IllegalStateException("'request' is not an OCSPStatusRequest");
    }

    public Object getRequest() {
        return this.request;
    }

    public short getStatusType() {
        return this.statusType;
    }
}