package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ocsp.OCSPResponse;

/* loaded from: classes2.dex */
public class CertificateStatus {
    protected Object response;
    protected short statusType;

    public CertificateStatus(short s, Object obj) {
        if (!isCorrectType(s, obj)) {
            throw new IllegalArgumentException("'response' is not an instance of the correct type");
        }
        this.statusType = s;
        this.response = obj;
    }

    protected static boolean isCorrectType(short s, Object obj) {
        if (s != 1) {
            if (s == 2) {
                return isOCSPResponseList(obj);
            }
            throw new IllegalArgumentException("'statusType' is an unsupported CertificateStatusType");
        }
        return obj instanceof OCSPResponse;
    }

    protected static boolean isOCSPResponseList(Object obj) {
        Vector vector;
        int size;
        if ((obj instanceof Vector) && (size = (vector = (Vector) obj).size()) >= 1) {
            for (int i = 0; i < size; i++) {
                Object elementAt = vector.elementAt(i);
                if (elementAt != null && !(elementAt instanceof OCSPResponse)) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static CertificateStatus parse(TlsContext tlsContext, InputStream inputStream) throws IOException {
        OCSPResponse oCSPResponse;
        SecurityParameters securityParametersHandshake = tlsContext.getSecurityParametersHandshake();
        Certificate peerCertificate = securityParametersHandshake.getPeerCertificate();
        if (peerCertificate == null || peerCertificate.isEmpty() || peerCertificate.getCertificateType() != 0) {
            throw new TlsFatalAlert((short) 80);
        }
        int length = peerCertificate.getLength();
        int statusRequestVersion = securityParametersHandshake.getStatusRequestVersion();
        short readUint8 = TlsUtils.readUint8(inputStream);
        if (readUint8 == 1) {
            requireStatusRequestVersion(1, statusRequestVersion);
            oCSPResponse = parseOCSPResponse(TlsUtils.readOpaque24(inputStream, 1));
        } else if (readUint8 != 2) {
            throw new TlsFatalAlert((short) 50);
        } else {
            requireStatusRequestVersion(2, statusRequestVersion);
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(TlsUtils.readOpaque24(inputStream, 1));
            Vector vector = new Vector();
            while (byteArrayInputStream.available() > 0) {
                if (vector.size() >= length) {
                    throw new TlsFatalAlert((short) 47);
                }
                int readUint24 = TlsUtils.readUint24(byteArrayInputStream);
                vector.addElement(readUint24 < 1 ? null : parseOCSPResponse(TlsUtils.readFully(readUint24, byteArrayInputStream)));
            }
            vector.trimToSize();
            oCSPResponse = vector;
        }
        return new CertificateStatus(readUint8, oCSPResponse);
    }

    protected static OCSPResponse parseOCSPResponse(byte[] bArr) throws IOException {
        OCSPResponse oCSPResponse = OCSPResponse.getInstance(TlsUtils.readASN1Object(bArr));
        TlsUtils.requireDEREncoding(oCSPResponse, bArr);
        return oCSPResponse;
    }

    protected static void requireStatusRequestVersion(int i, int i2) throws IOException {
        if (i2 < i) {
            throw new TlsFatalAlert((short) 50);
        }
    }

    public void encode(OutputStream outputStream) throws IOException {
        byte[] encoded;
        TlsUtils.writeUint8(this.statusType, outputStream);
        short s = this.statusType;
        if (s == 1) {
            TlsUtils.writeOpaque24(((OCSPResponse) this.response).getEncoded(ASN1Encoding.DER), outputStream);
        } else if (s != 2) {
            throw new TlsFatalAlert((short) 80);
        } else {
            Vector vector = (Vector) this.response;
            int size = vector.size();
            Vector vector2 = new Vector(size);
            long j = 0;
            for (int i = 0; i < size; i++) {
                OCSPResponse oCSPResponse = (OCSPResponse) vector.elementAt(i);
                if (oCSPResponse == null) {
                    vector2.addElement(TlsUtils.EMPTY_BYTES);
                } else {
                    vector2.addElement(oCSPResponse.getEncoded(ASN1Encoding.DER));
                    j += encoded.length;
                }
                j += 3;
            }
            TlsUtils.checkUint24(j);
            TlsUtils.writeUint24((int) j, outputStream);
            for (int i2 = 0; i2 < size; i2++) {
                TlsUtils.writeOpaque24((byte[]) vector2.elementAt(i2), outputStream);
            }
        }
    }

    public OCSPResponse getOCSPResponse() {
        if (isCorrectType((short) 1, this.response)) {
            return (OCSPResponse) this.response;
        }
        throw new IllegalStateException("'response' is not an OCSPResponse");
    }

    public Vector getOCSPResponseList() {
        if (isCorrectType((short) 2, this.response)) {
            return (Vector) this.response;
        }
        throw new IllegalStateException("'response' is not an OCSPResponseList");
    }

    public Object getResponse() {
        return this.response;
    }

    public short getStatusType() {
        return this.statusType;
    }
}