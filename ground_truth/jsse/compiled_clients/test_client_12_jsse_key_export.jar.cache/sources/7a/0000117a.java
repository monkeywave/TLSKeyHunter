package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.util.HexDumpEncoder;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLExtensions.class */
public final class SSLExtensions {
    private final SSLHandshake.HandshakeMessage handshakeMessage;
    private Map<SSLExtension, byte[]> extMap = new LinkedHashMap();
    private int encodedLength;
    private final Map<Integer, byte[]> logMap;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLExtensions(SSLHandshake.HandshakeMessage handshakeMessage) {
        this.logMap = SSLLogger.isOn ? new LinkedHashMap() : null;
        this.handshakeMessage = handshakeMessage;
        this.encodedLength = 2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLExtensions(SSLHandshake.HandshakeMessage hm, ByteBuffer m, SSLExtension[] extensions) throws IOException {
        this.logMap = SSLLogger.isOn ? new LinkedHashMap() : null;
        this.handshakeMessage = hm;
        int len = Record.getInt16(m);
        this.encodedLength = len + 2;
        while (len > 0) {
            int extId = Record.getInt16(m);
            int extLen = Record.getInt16(m);
            if (extLen > m.remaining()) {
                throw hm.handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Error parsing extension (" + extId + "): no sufficient data");
            }
            boolean isSupported = true;
            SSLHandshake handshakeType = hm.handshakeType();
            if (SSLExtension.isConsumable(extId) && SSLExtension.valueOf(handshakeType, extId) == null) {
                if (extId == SSLExtension.CH_SUPPORTED_GROUPS.f986id && handshakeType == SSLHandshake.SERVER_HELLO) {
                    isSupported = false;
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.warning("Received buggy supported_groups extension in the ServerHello handshake message", new Object[0]);
                    }
                } else if (handshakeType == SSLHandshake.SERVER_HELLO) {
                    throw hm.handshakeContext.conContext.fatal(Alert.UNSUPPORTED_EXTENSION, "extension (" + extId + ") should not be presented in " + handshakeType.name);
                } else {
                    isSupported = false;
                }
            }
            if (isSupported) {
                isSupported = false;
                int length = extensions.length;
                int i = 0;
                while (true) {
                    if (i >= length) {
                        break;
                    }
                    SSLExtension extension = extensions[i];
                    if (extension.f986id != extId || extension.onLoadConsumer == null) {
                        i++;
                    } else if (extension.handshakeType != handshakeType) {
                        throw hm.handshakeContext.conContext.fatal(Alert.UNSUPPORTED_EXTENSION, "extension (" + extId + ") should not be presented in " + handshakeType.name);
                    } else {
                        byte[] extData = new byte[extLen];
                        m.get(extData);
                        this.extMap.put(extension, extData);
                        if (this.logMap != null) {
                            this.logMap.put(Integer.valueOf(extId), extData);
                        }
                        isSupported = true;
                    }
                }
            }
            if (!isSupported) {
                if (this.logMap != null) {
                    byte[] extData2 = new byte[extLen];
                    m.get(extData2);
                    this.logMap.put(Integer.valueOf(extId), extData2);
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("Ignore unknown or unsupported extension", toString(extId, extData2));
                    }
                } else {
                    int pos = m.position() + extLen;
                    m.position(pos);
                }
            }
            len -= extLen + 4;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] get(SSLExtension ext) {
        return this.extMap.get(ext);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void consumeOnLoad(HandshakeContext context, SSLExtension[] extensions) throws IOException {
        for (SSLExtension extension : extensions) {
            if (context.negotiatedProtocol != null && !extension.isAvailable(context.negotiatedProtocol)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unsupported extension: " + extension.name, new Object[0]);
                }
            } else if (!this.extMap.containsKey(extension)) {
                if (extension.onLoadAbsence != null) {
                    extension.absentOnLoad(context, this.handshakeMessage);
                } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " + extension.name, new Object[0]);
                }
            } else if (extension.onLoadConsumer == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("Ignore unsupported extension: " + extension.name, new Object[0]);
                }
            } else {
                ByteBuffer m = ByteBuffer.wrap(this.extMap.get(extension));
                extension.consumeOnLoad(context, this.handshakeMessage, m);
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Consumed extension: " + extension.name, new Object[0]);
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void consumeOnTrade(HandshakeContext context, SSLExtension[] extensions) throws IOException {
        for (SSLExtension extension : extensions) {
            if (!this.extMap.containsKey(extension)) {
                if (extension.onTradeAbsence != null) {
                    extension.absentOnTrade(context, this.handshakeMessage);
                } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " + extension.name, new Object[0]);
                }
            } else if (extension.onTradeConsumer == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("Ignore impact of unsupported extension: " + extension.name, new Object[0]);
                }
            } else {
                extension.consumeOnTrade(context, this.handshakeMessage);
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Populated with extension: " + extension.name, new Object[0]);
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void produce(HandshakeContext context, SSLExtension[] extensions) throws IOException {
        for (SSLExtension extension : extensions) {
            if (this.extMap.containsKey(extension)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore, duplicated extension: " + extension.name, new Object[0]);
                }
            } else if (extension.networkProducer == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("Ignore, no extension producer defined: " + extension.name, new Object[0]);
                }
            } else {
                byte[] encoded = extension.produce(context, this.handshakeMessage);
                if (encoded != null) {
                    this.extMap.put(extension, encoded);
                    this.encodedLength += encoded.length + 4;
                } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore, context unavailable extension: " + extension.name, new Object[0]);
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void reproduce(HandshakeContext context, SSLExtension[] extensions) throws IOException {
        for (SSLExtension extension : extensions) {
            if (extension.networkProducer == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("Ignore, no extension producer defined: " + extension.name, new Object[0]);
                }
            } else {
                byte[] encoded = extension.produce(context, this.handshakeMessage);
                if (encoded != null) {
                    if (this.extMap.containsKey(extension)) {
                        byte[] old = this.extMap.replace(extension, encoded);
                        if (old != null) {
                            this.encodedLength -= old.length + 4;
                        }
                        this.encodedLength += encoded.length + 4;
                    } else {
                        this.extMap.put(extension, encoded);
                        this.encodedLength += encoded.length + 4;
                    }
                } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore, context unavailable extension: " + extension.name, new Object[0]);
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int length() {
        if (this.extMap.isEmpty()) {
            return 0;
        }
        return this.encodedLength;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void send(HandshakeOutStream hos) throws IOException {
        SSLExtension[] values;
        int extsLen = length();
        if (extsLen == 0) {
            return;
        }
        hos.putInt16(extsLen - 2);
        for (SSLExtension ext : SSLExtension.values()) {
            byte[] extData = this.extMap.get(ext);
            if (extData != null) {
                hos.putInt16(ext.f986id);
                hos.putBytes16(extData);
            }
        }
    }

    public String toString() {
        if (this.extMap.isEmpty() && (this.logMap == null || this.logMap.isEmpty())) {
            return "<no extension>";
        }
        StringBuilder builder = new StringBuilder(512);
        if (this.logMap != null && !this.logMap.isEmpty()) {
            for (Map.Entry<Integer, byte[]> en : this.logMap.entrySet()) {
                SSLExtension ext = SSLExtension.valueOf(this.handshakeMessage.handshakeType(), en.getKey().intValue());
                if (builder.length() != 0) {
                    builder.append(",\n");
                }
                if (ext != null) {
                    builder.append(ext.toString(ByteBuffer.wrap(en.getValue())));
                } else {
                    builder.append(toString(en.getKey().intValue(), en.getValue()));
                }
            }
            return builder.toString();
        }
        for (Map.Entry<SSLExtension, byte[]> en2 : this.extMap.entrySet()) {
            if (builder.length() != 0) {
                builder.append(",\n");
            }
            builder.append(en2.getKey().toString(ByteBuffer.wrap(en2.getValue())));
        }
        return builder.toString();
    }

    private static String toString(int extId, byte[] extData) {
        String extName = SSLExtension.nameOf(extId);
        MessageFormat messageFormat = new MessageFormat("\"{0} ({1})\": '{'\n{2}\n'}'", Locale.ENGLISH);
        HexDumpEncoder hexEncoder = new HexDumpEncoder();
        String encoded = hexEncoder.encodeBuffer(extData);
        Object[] messageFields = {extName, Integer.valueOf(extId), Utilities.indent(encoded)};
        return messageFormat.format(messageFields);
    }
}