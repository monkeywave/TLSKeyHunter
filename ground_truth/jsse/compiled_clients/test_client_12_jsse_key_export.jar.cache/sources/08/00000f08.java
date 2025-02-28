package org.bouncycastle.util.p012io.pem;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import org.bouncycastle.util.encoders.Base64;

/* renamed from: org.bouncycastle.util.io.pem.PemReader */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/io/pem/PemReader.class */
public class PemReader extends BufferedReader {
    private static final String BEGIN = "-----BEGIN ";
    private static final String END = "-----END ";

    public PemReader(Reader reader) {
        super(reader);
    }

    public PemObject readPemObject() throws IOException {
        String str;
        String substring;
        int indexOf;
        String readLine = readLine();
        while (true) {
            str = readLine;
            if (str == null || str.startsWith(BEGIN)) {
                break;
            }
            readLine = readLine();
        }
        if (str == null || (indexOf = (substring = str.substring(BEGIN.length())).indexOf(45)) <= 0 || !substring.endsWith("-----") || substring.length() - indexOf != 5) {
            return null;
        }
        return loadObject(substring.substring(0, indexOf));
    }

    private PemObject loadObject(String str) throws IOException {
        String readLine;
        String str2 = END + str;
        StringBuffer stringBuffer = new StringBuffer();
        ArrayList arrayList = new ArrayList();
        while (true) {
            readLine = readLine();
            if (readLine == null) {
                break;
            }
            int indexOf = readLine.indexOf(58);
            if (indexOf >= 0) {
                arrayList.add(new PemHeader(readLine.substring(0, indexOf), readLine.substring(indexOf + 1).trim()));
            } else if (readLine.indexOf(str2) != -1) {
                break;
            } else {
                stringBuffer.append(readLine.trim());
            }
        }
        if (readLine == null) {
            throw new IOException(str2 + " not found");
        }
        return new PemObject(str, arrayList, Base64.decode(stringBuffer.toString()));
    }
}