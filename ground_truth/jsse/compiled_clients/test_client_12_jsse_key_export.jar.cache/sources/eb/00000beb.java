package org.bouncycastle.jce.provider;

import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Base64;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/provider/PEMUtil.class */
public class PEMUtil {
    private final String _header1;
    private final String _header2;
    private final String _footer1;
    private final String _footer2;

    /* JADX INFO: Access modifiers changed from: package-private */
    public PEMUtil(String str) {
        this._header1 = "-----BEGIN " + str + "-----";
        this._header2 = "-----BEGIN X509 " + str + "-----";
        this._footer1 = "-----END " + str + "-----";
        this._footer2 = "-----END X509 " + str + "-----";
    }

    private String readLine(InputStream inputStream) throws IOException {
        int read;
        StringBuffer stringBuffer = new StringBuffer();
        while (true) {
            read = inputStream.read();
            if (read == 13 || read == 10 || read < 0) {
                if (read < 0 || stringBuffer.length() != 0) {
                    break;
                }
            } else if (read != 13) {
                stringBuffer.append((char) read);
            }
        }
        if (read < 0) {
            return null;
        }
        return stringBuffer.toString();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1Sequence readPEMObject(InputStream inputStream) throws IOException {
        String readLine;
        StringBuffer stringBuffer = new StringBuffer();
        do {
            readLine = readLine(inputStream);
            if (readLine == null || readLine.startsWith(this._header1)) {
                break;
            }
        } while (!readLine.startsWith(this._header2));
        while (true) {
            String readLine2 = readLine(inputStream);
            if (readLine2 == null || readLine2.startsWith(this._footer1) || readLine2.startsWith(this._footer2)) {
                break;
            }
            stringBuffer.append(readLine2);
        }
        if (stringBuffer.length() != 0) {
            ASN1Primitive readObject = new ASN1InputStream(Base64.decode(stringBuffer.toString())).readObject();
            if (readObject instanceof ASN1Sequence) {
                return (ASN1Sequence) readObject;
            }
            throw new IOException("malformed PEM data encountered");
        }
        return null;
    }
}