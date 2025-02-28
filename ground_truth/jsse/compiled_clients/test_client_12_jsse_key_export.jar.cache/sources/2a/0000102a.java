package org.openjsse.sun.security.ssl;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ContentType.class */
enum ContentType {
    INVALID((byte) 0, "invalid", ProtocolVersion.PROTOCOLS_OF_13),
    CHANGE_CIPHER_SPEC((byte) 20, "change_cipher_spec", ProtocolVersion.PROTOCOLS_TO_12),
    ALERT((byte) 21, "alert", ProtocolVersion.PROTOCOLS_TO_13),
    HANDSHAKE((byte) 22, "handshake", ProtocolVersion.PROTOCOLS_TO_13),
    APPLICATION_DATA((byte) 23, "application_data", ProtocolVersion.PROTOCOLS_TO_13);
    

    /* renamed from: id */
    final byte f965id;
    final String name;
    final ProtocolVersion[] supportedProtocols;

    ContentType(byte id, String name, ProtocolVersion[] supportedProtocols) {
        this.f965id = id;
        this.name = name;
        this.supportedProtocols = supportedProtocols;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ContentType valueOf(byte id) {
        ContentType[] values;
        for (ContentType ct : values()) {
            if (ct.f965id == id) {
                return ct;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String nameOf(byte id) {
        ContentType[] values;
        for (ContentType ct : values()) {
            if (ct.f965id == id) {
                return ct.name;
            }
        }
        return "<UNKNOWN CONTENT TYPE: " + (id & 255) + ">";
    }
}