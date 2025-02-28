package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Base64;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/x509/PEMUtil.class */
public class PEMUtil {
    private final Boundaries[] _supportedBoundaries;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/x509/PEMUtil$Boundaries.class */
    public class Boundaries {
        private final String _header;
        private final String _footer;

        private Boundaries(String str) {
            this._header = "-----BEGIN " + str + "-----";
            this._footer = "-----END " + str + "-----";
        }

        public boolean isTheExpectedHeader(String str) {
            return str.startsWith(this._header);
        }

        public boolean isTheExpectedFooter(String str) {
            return str.startsWith(this._footer);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PEMUtil(String str) {
        this._supportedBoundaries = new Boundaries[]{new Boundaries(str), new Boundaries("X509 " + str), new Boundaries("PKCS7")};
    }

    private String readLine(InputStream inputStream) throws IOException {
        int read;
        StringBuffer stringBuffer = new StringBuffer();
        while (true) {
            read = inputStream.read();
            if (read != 13 && read != 10 && read >= 0) {
                stringBuffer.append((char) read);
            } else if (read < 0 || stringBuffer.length() != 0) {
                break;
            }
        }
        if (read < 0) {
            if (stringBuffer.length() == 0) {
                return null;
            }
            return stringBuffer.toString();
        }
        if (read == 13) {
            inputStream.mark(1);
            int read2 = inputStream.read();
            if (read2 == 10) {
                inputStream.mark(1);
            }
            if (read2 > 0) {
                inputStream.reset();
            }
        }
        return stringBuffer.toString();
    }

    private Boundaries getBoundaries(String str) {
        for (int i = 0; i != this._supportedBoundaries.length; i++) {
            Boundaries boundaries = this._supportedBoundaries[i];
            if (boundaries.isTheExpectedHeader(str) || boundaries.isTheExpectedFooter(str)) {
                return boundaries;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1Sequence readPEMObject(InputStream inputStream, boolean z) throws IOException {
        String readLine;
        String readLine2;
        StringBuffer stringBuffer = new StringBuffer();
        Boundaries boundaries = null;
        while (boundaries == null && (readLine2 = readLine(inputStream)) != null) {
            boundaries = getBoundaries(readLine2);
            if (boundaries != null && !boundaries.isTheExpectedHeader(readLine2)) {
                throw new IOException("malformed PEM data: found footer where header was expected");
            }
        }
        if (boundaries == null) {
            if (z) {
                throw new IOException("malformed PEM data: no header found");
            }
            return null;
        }
        Boundaries boundaries2 = null;
        while (boundaries2 == null && (readLine = readLine(inputStream)) != null) {
            boundaries2 = getBoundaries(readLine);
            if (boundaries2 == null) {
                stringBuffer.append(readLine);
            } else if (!boundaries.isTheExpectedFooter(readLine)) {
                throw new IOException("malformed PEM data: header/footer mismatch");
            }
        }
        if (boundaries2 == null) {
            throw new IOException("malformed PEM data: no footer found");
        }
        if (stringBuffer.length() != 0) {
            try {
                return ASN1Sequence.getInstance(Base64.decode(stringBuffer.toString()));
            } catch (Exception e) {
                throw new IOException("malformed PEM data encountered");
            }
        }
        return null;
    }
}