package org.openjsse.sun.security.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import org.bouncycastle.i18n.LocalizedMessage;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/HexDumpEncoder.class */
public class HexDumpEncoder {
    private int offset;
    private int thisLineLength;
    private int currentByte;
    private byte[] thisLine = new byte[16];
    protected PrintStream pStream;

    static void hexDigit(PrintStream p, byte x) {
        char c;
        char c2;
        char c3 = (char) ((x >> 4) & 15);
        if (c3 > '\t') {
            c = (char) ((c3 - '\n') + 65);
        } else {
            c = (char) (c3 + '0');
        }
        p.write(c);
        char c4 = (char) (x & 15);
        if (c4 > '\t') {
            c2 = (char) ((c4 - '\n') + 65);
        } else {
            c2 = (char) (c4 + '0');
        }
        p.write(c2);
    }

    protected int bytesPerAtom() {
        return 1;
    }

    protected int bytesPerLine() {
        return 16;
    }

    protected void encodeBufferPrefix(OutputStream o) throws IOException {
        this.offset = 0;
        this.pStream = new PrintStream(o);
    }

    protected void encodeLinePrefix(OutputStream o, int len) throws IOException {
        hexDigit(this.pStream, (byte) ((this.offset >>> 8) & GF2Field.MASK));
        hexDigit(this.pStream, (byte) (this.offset & GF2Field.MASK));
        this.pStream.print(": ");
        this.currentByte = 0;
        this.thisLineLength = len;
    }

    protected void encodeAtom(OutputStream o, byte[] buf, int off, int len) throws IOException {
        this.thisLine[this.currentByte] = buf[off];
        hexDigit(this.pStream, buf[off]);
        this.pStream.print(" ");
        this.currentByte++;
        if (this.currentByte == 8) {
            this.pStream.print("  ");
        }
    }

    protected void encodeLineSuffix(OutputStream o) throws IOException {
        if (this.thisLineLength < 16) {
            for (int i = this.thisLineLength; i < 16; i++) {
                this.pStream.print("   ");
                if (i == 7) {
                    this.pStream.print("  ");
                }
            }
        }
        this.pStream.print(" ");
        for (int i2 = 0; i2 < this.thisLineLength; i2++) {
            if (this.thisLine[i2] < 32 || this.thisLine[i2] > 122) {
                this.pStream.print(".");
            } else {
                this.pStream.write(this.thisLine[i2]);
            }
        }
        this.pStream.println();
        this.offset += this.thisLineLength;
    }

    protected int readFully(InputStream in, byte[] buffer) throws IOException {
        for (int i = 0; i < buffer.length; i++) {
            int q = in.read();
            if (q == -1) {
                return i;
            }
            buffer[i] = (byte) q;
        }
        return buffer.length;
    }

    public void encode(InputStream inStream, OutputStream outStream) throws IOException {
        byte[] tmpbuffer = new byte[bytesPerLine()];
        encodeBufferPrefix(outStream);
        while (true) {
            int numBytes = readFully(inStream, tmpbuffer);
            if (numBytes != 0) {
                encodeLinePrefix(outStream, numBytes);
                int i = 0;
                while (true) {
                    int j = i;
                    if (j >= numBytes) {
                        break;
                    }
                    if (j + bytesPerAtom() <= numBytes) {
                        encodeAtom(outStream, tmpbuffer, j, bytesPerAtom());
                    } else {
                        encodeAtom(outStream, tmpbuffer, j, numBytes - j);
                    }
                    i = j + bytesPerAtom();
                }
                if (numBytes >= bytesPerLine()) {
                    encodeLineSuffix(outStream);
                } else {
                    return;
                }
            } else {
                return;
            }
        }
    }

    public String encode(byte[] aBuffer) {
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        ByteArrayInputStream inStream = new ByteArrayInputStream(aBuffer);
        try {
            encode(inStream, outStream);
            String retVal = outStream.toString(LocalizedMessage.DEFAULT_ENCODING);
            return retVal;
        } catch (Exception e) {
            throw new Error("CharacterEncoder.encode internal error");
        }
    }

    private byte[] getBytes(ByteBuffer bb) {
        byte[] buf = null;
        if (bb.hasArray()) {
            byte[] tmp = bb.array();
            if (tmp.length == bb.capacity() && tmp.length == bb.remaining()) {
                buf = tmp;
                bb.position(bb.limit());
            }
        }
        if (buf == null) {
            buf = new byte[bb.remaining()];
            bb.get(buf);
        }
        return buf;
    }

    public String encode(ByteBuffer aBuffer) {
        byte[] buf = getBytes(aBuffer);
        return encode(buf);
    }

    public void encodeBuffer(InputStream inStream, OutputStream outStream) throws IOException {
        int numBytes;
        byte[] tmpbuffer = new byte[bytesPerLine()];
        encodeBufferPrefix(outStream);
        do {
            numBytes = readFully(inStream, tmpbuffer);
            if (numBytes != 0) {
                encodeLinePrefix(outStream, numBytes);
                int i = 0;
                while (true) {
                    int j = i;
                    if (j < numBytes) {
                        if (j + bytesPerAtom() <= numBytes) {
                            encodeAtom(outStream, tmpbuffer, j, bytesPerAtom());
                        } else {
                            encodeAtom(outStream, tmpbuffer, j, numBytes - j);
                        }
                        i = j + bytesPerAtom();
                    } else {
                        encodeLineSuffix(outStream);
                    }
                }
            } else {
                return;
            }
        } while (numBytes >= bytesPerLine());
    }

    public void encodeBuffer(byte[] aBuffer, OutputStream aStream) throws IOException {
        ByteArrayInputStream inStream = new ByteArrayInputStream(aBuffer);
        encodeBuffer(inStream, aStream);
    }

    public String encodeBuffer(byte[] aBuffer) {
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        ByteArrayInputStream inStream = new ByteArrayInputStream(aBuffer);
        try {
            encodeBuffer(inStream, outStream);
            return outStream.toString();
        } catch (Exception e) {
            throw new Error("CharacterEncoder.encodeBuffer internal error");
        }
    }

    public void encodeBuffer(ByteBuffer aBuffer, OutputStream aStream) throws IOException {
        byte[] buf = getBytes(aBuffer);
        encodeBuffer(buf, aStream);
    }
}