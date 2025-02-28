package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import javax.net.ssl.SSLException;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Record.class */
interface Record {
    public static final int maxMacSize = 48;
    public static final int maxDataSize = 16384;
    public static final int maxPadding = 256;
    public static final int maxIVLength = 16;
    public static final int maxFragmentSize = 18432;
    public static final boolean enableCBCProtection = Utilities.getBooleanProperty("jsse.enableCBCProtection", true);
    public static final int OVERFLOW_OF_INT08 = 256;
    public static final int OVERFLOW_OF_INT16 = 65536;
    public static final int OVERFLOW_OF_INT24 = 16777216;

    static int getInt8(ByteBuffer m) throws IOException {
        verifyLength(m, 1);
        return m.get() & 255;
    }

    static int getInt16(ByteBuffer m) throws IOException {
        verifyLength(m, 2);
        return ((m.get() & 255) << 8) | (m.get() & 255);
    }

    static int getInt24(ByteBuffer m) throws IOException {
        verifyLength(m, 3);
        return ((m.get() & 255) << 16) | ((m.get() & 255) << 8) | (m.get() & 255);
    }

    static int getInt32(ByteBuffer m) throws IOException {
        verifyLength(m, 4);
        return ((m.get() & 255) << 24) | ((m.get() & 255) << 16) | ((m.get() & 255) << 8) | (m.get() & 255);
    }

    static byte[] getBytes8(ByteBuffer m) throws IOException {
        int len = getInt8(m);
        verifyLength(m, len);
        byte[] b = new byte[len];
        m.get(b);
        return b;
    }

    static byte[] getBytes16(ByteBuffer m) throws IOException {
        int len = getInt16(m);
        verifyLength(m, len);
        byte[] b = new byte[len];
        m.get(b);
        return b;
    }

    static byte[] getBytes24(ByteBuffer m) throws IOException {
        int len = getInt24(m);
        verifyLength(m, len);
        byte[] b = new byte[len];
        m.get(b);
        return b;
    }

    static void putInt8(ByteBuffer m, int i) throws IOException {
        verifyLength(m, 1);
        m.put((byte) (i & GF2Field.MASK));
    }

    static void putInt16(ByteBuffer m, int i) throws IOException {
        verifyLength(m, 2);
        m.put((byte) ((i >> 8) & GF2Field.MASK));
        m.put((byte) (i & GF2Field.MASK));
    }

    static void putInt24(ByteBuffer m, int i) throws IOException {
        verifyLength(m, 3);
        m.put((byte) ((i >> 16) & GF2Field.MASK));
        m.put((byte) ((i >> 8) & GF2Field.MASK));
        m.put((byte) (i & GF2Field.MASK));
    }

    static void putInt32(ByteBuffer m, int i) throws IOException {
        m.put((byte) ((i >> 24) & GF2Field.MASK));
        m.put((byte) ((i >> 16) & GF2Field.MASK));
        m.put((byte) ((i >> 8) & GF2Field.MASK));
        m.put((byte) (i & GF2Field.MASK));
    }

    static void putBytes8(ByteBuffer m, byte[] s) throws IOException {
        if (s == null || s.length == 0) {
            verifyLength(m, 1);
            putInt8(m, 0);
            return;
        }
        verifyLength(m, 1 + s.length);
        putInt8(m, s.length);
        m.put(s);
    }

    static void putBytes16(ByteBuffer m, byte[] s) throws IOException {
        if (s == null || s.length == 0) {
            verifyLength(m, 2);
            putInt16(m, 0);
            return;
        }
        verifyLength(m, 2 + s.length);
        putInt16(m, s.length);
        m.put(s);
    }

    static void putBytes24(ByteBuffer m, byte[] s) throws IOException {
        if (s == null || s.length == 0) {
            verifyLength(m, 3);
            putInt24(m, 0);
            return;
        }
        verifyLength(m, 3 + s.length);
        putInt24(m, s.length);
        m.put(s);
    }

    static void verifyLength(ByteBuffer m, int len) throws SSLException {
        if (len > m.remaining()) {
            throw new SSLException("Insufficient space in the buffer, may be cause by an unexpected end of handshake data.");
        }
    }
}