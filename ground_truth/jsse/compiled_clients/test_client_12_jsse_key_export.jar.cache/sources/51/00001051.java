package org.openjsse.sun.security.ssl;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DTLSRecord.class */
interface DTLSRecord extends Record {
    public static final int headerSize = 13;
    public static final int handshakeHeaderSize = 12;
    public static final int headerPlusMaxIVSize = 29;
    public static final int maxPlaintextPlusSize = 333;
    public static final int maxRecordSize = 16717;
    public static final int minCertPlaintextSize = 28;
}