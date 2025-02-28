package org.bouncycastle.util.p012io.pem;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Writer;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

/* renamed from: org.bouncycastle.util.io.pem.PemWriter */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/io/pem/PemWriter.class */
public class PemWriter extends BufferedWriter {
    private static final int LINE_LENGTH = 64;
    private final int nlLength;
    private char[] buf;

    public PemWriter(Writer writer) {
        super(writer);
        this.buf = new char[64];
        String lineSeparator = Strings.lineSeparator();
        if (lineSeparator != null) {
            this.nlLength = lineSeparator.length();
        } else {
            this.nlLength = 2;
        }
    }

    public int getOutputSize(PemObject pemObject) {
        int length = (2 * (pemObject.getType().length() + 10 + this.nlLength)) + 6 + 4;
        if (!pemObject.getHeaders().isEmpty()) {
            for (PemHeader pemHeader : pemObject.getHeaders()) {
                length += pemHeader.getName().length() + ": ".length() + pemHeader.getValue().length() + this.nlLength;
            }
            length += this.nlLength;
        }
        int length2 = ((pemObject.getContent().length + 2) / 3) * 4;
        return length + length2 + ((((length2 + 64) - 1) / 64) * this.nlLength);
    }

    public void writeObject(PemObjectGenerator pemObjectGenerator) throws IOException {
        PemObject generate = pemObjectGenerator.generate();
        writePreEncapsulationBoundary(generate.getType());
        if (!generate.getHeaders().isEmpty()) {
            for (PemHeader pemHeader : generate.getHeaders()) {
                write(pemHeader.getName());
                write(": ");
                write(pemHeader.getValue());
                newLine();
            }
            newLine();
        }
        writeEncoded(generate.getContent());
        writePostEncapsulationBoundary(generate.getType());
    }

    private void writeEncoded(byte[] bArr) throws IOException {
        byte[] encode = Base64.encode(bArr);
        int i = 0;
        while (true) {
            int i2 = i;
            if (i2 >= encode.length) {
                return;
            }
            int i3 = 0;
            while (i3 != this.buf.length && i2 + i3 < encode.length) {
                this.buf[i3] = (char) encode[i2 + i3];
                i3++;
            }
            write(this.buf, 0, i3);
            newLine();
            i = i2 + this.buf.length;
        }
    }

    private void writePreEncapsulationBoundary(String str) throws IOException {
        write("-----BEGIN " + str + "-----");
        newLine();
    }

    private void writePostEncapsulationBoundary(String str) throws IOException {
        write("-----END " + str + "-----");
        newLine();
    }
}