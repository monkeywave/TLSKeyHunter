package org.bouncycastle.util.p019io.pem;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.util.encoders.Base64;

/* renamed from: org.bouncycastle.util.io.pem.PemReader */
/* loaded from: classes2.dex */
public class PemReader extends BufferedReader {
    private static final String BEGIN = "-----BEGIN ";
    private static final String END = "-----END ";
    public static final String LAX_PEM_PARSING_SYSTEM_PROPERTY_NAME = "org.bouncycastle.pemreader.lax";
    private static final Logger LOG = Logger.getLogger(PemReader.class.getName());

    public PemReader(Reader reader) {
        super(reader);
    }

    private PemObject loadObject(String str) throws IOException {
        String readLine;
        String str2 = END + str + "-----";
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
            } else {
                if (System.getProperty(LAX_PEM_PARSING_SYSTEM_PROPERTY_NAME, "false").equalsIgnoreCase("true")) {
                    String trim = readLine.trim();
                    if (!trim.equals(readLine)) {
                        Logger logger = LOG;
                        if (logger.isLoggable(Level.WARNING)) {
                            logger.log(Level.WARNING, "PEM object contains whitespaces on -----END line", (Throwable) new Exception("trace"));
                        }
                    }
                    readLine = trim;
                }
                if (readLine.indexOf(str2) == 0) {
                    break;
                }
                stringBuffer.append(readLine.trim());
            }
        }
        if (readLine != null) {
            return new PemObject(str, arrayList, Base64.decode(stringBuffer.toString()));
        }
        throw new IOException(str2 + " not found");
    }

    public PemObject readPemObject() throws IOException {
        String readLine;
        String trim;
        int indexOf;
        do {
            readLine = readLine();
            if (readLine == null) {
                break;
            }
        } while (!readLine.startsWith(BEGIN));
        if (readLine == null || (indexOf = (trim = readLine.substring(BEGIN.length()).trim()).indexOf(45)) <= 0 || !trim.endsWith("-----") || trim.length() - indexOf != 5) {
            return null;
        }
        return loadObject(trim.substring(0, indexOf));
    }
}