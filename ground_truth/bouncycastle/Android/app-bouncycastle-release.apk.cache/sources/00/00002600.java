package org.bouncycastle.jce.provider;

import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Base64;

/* loaded from: classes2.dex */
public class PEMUtil {
    private final String _footer1;
    private final String _footer2;
    private final String _header1;
    private final String _header2;

    /* JADX INFO: Access modifiers changed from: package-private */
    public PEMUtil(String str) {
        this._header1 = "-----BEGIN " + str + "-----";
        this._header2 = "-----BEGIN X509 " + str + "-----";
        this._footer1 = "-----END " + str + "-----";
        this._footer2 = "-----END X509 " + str + "-----";
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0021, code lost:
        if (r0.length() == 0) goto L17;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private java.lang.String readLine(java.io.InputStream r5) throws java.io.IOException {
        /*
            r4 = this;
            java.lang.StringBuffer r0 = new java.lang.StringBuffer
            r0.<init>()
        L5:
            int r1 = r5.read()
            r2 = 13
            if (r1 == r2) goto L1b
            r3 = 10
            if (r1 == r3) goto L1b
            if (r1 < 0) goto L1b
            if (r1 != r2) goto L16
            goto L5
        L16:
            char r1 = (char) r1
            r0.append(r1)
            goto L5
        L1b:
            if (r1 < 0) goto L23
            int r2 = r0.length()
            if (r2 == 0) goto L5
        L23:
            if (r1 >= 0) goto L27
            r5 = 0
            return r5
        L27:
            java.lang.String r5 = r0.toString()
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.jce.provider.PEMUtil.readLine(java.io.InputStream):java.lang.String");
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