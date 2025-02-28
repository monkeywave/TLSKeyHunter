package org.openjsse.sun.security.ssl;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLRecord.class */
interface SSLRecord extends Record {
    public static final int headerSize = 5;
    public static final int handshakeHeaderSize = 4;
    public static final int headerPlusMaxIVSize = 21;
    public static final int maxPlaintextPlusSize = 325;
    public static final int maxRecordSize = 16709;
    public static final int maxLargeRecordSize = 33093;
    public static final byte[] v2NoCipher = {Byte.MIN_VALUE, 3, 0, 0, 1};
}