package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.AccessController;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.net.ssl.SSLProtocolException;
import org.openjsse.javax.net.ssl.SSLEngine;
import org.openjsse.javax.net.ssl.SSLSocket;
import org.openjsse.sun.security.ssl.SSLExtension;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/AlpnExtension.class */
final class AlpnExtension {
    static final HandshakeProducer chNetworkProducer = new CHAlpnProducer();
    static final SSLExtension.ExtensionConsumer chOnLoadConsumer = new CHAlpnConsumer();
    static final HandshakeAbsence chOnLoadAbsence = new CHAlpnAbsence();
    static final HandshakeProducer shNetworkProducer = new SHAlpnProducer();
    static final SSLExtension.ExtensionConsumer shOnLoadConsumer = new SHAlpnConsumer();
    static final HandshakeAbsence shOnLoadAbsence = new SHAlpnAbsence();
    static final HandshakeProducer eeNetworkProducer = new SHAlpnProducer();
    static final SSLExtension.ExtensionConsumer eeOnLoadConsumer = new SHAlpnConsumer();
    static final HandshakeAbsence eeOnLoadAbsence = new SHAlpnAbsence();
    static final SSLStringizer alpnStringizer = new AlpnStringizer();
    static final Charset alpnCharset;

    AlpnExtension() {
    }

    static {
        String alpnCharsetString = (String) AccessController.doPrivileged(() -> {
            return Security.getProperty("jdk.tls.alpnCharset");
        });
        alpnCharsetString = (alpnCharsetString == null || alpnCharsetString.length() == 0) ? "ISO_8859_1" : "ISO_8859_1";
        alpnCharset = Charset.forName(alpnCharsetString);
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/AlpnExtension$AlpnSpec.class */
    static final class AlpnSpec implements SSLExtension.SSLExtensionSpec {
        final List<String> applicationProtocols;

        private AlpnSpec(String[] applicationProtocols) {
            this.applicationProtocols = Collections.unmodifiableList(Arrays.asList(applicationProtocols));
        }

        private AlpnSpec(ByteBuffer buffer) throws IOException {
            if (buffer.remaining() < 2) {
                throw new SSLProtocolException("Invalid application_layer_protocol_negotiation: insufficient data (length=" + buffer.remaining() + ")");
            }
            int listLen = Record.getInt16(buffer);
            if (listLen < 2 || listLen != buffer.remaining()) {
                throw new SSLProtocolException("Invalid application_layer_protocol_negotiation: incorrect list length (length=" + listLen + ")");
            }
            List<String> protocolNames = new LinkedList<>();
            while (buffer.hasRemaining()) {
                byte[] bytes = Record.getBytes8(buffer);
                if (bytes.length == 0) {
                    throw new SSLProtocolException("Invalid application_layer_protocol_negotiation extension: empty application protocol name");
                }
                String appProtocol = new String(bytes, AlpnExtension.alpnCharset);
                protocolNames.add(appProtocol);
            }
            this.applicationProtocols = Collections.unmodifiableList(protocolNames);
        }

        public String toString() {
            return this.applicationProtocols.toString();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/AlpnExtension$AlpnStringizer.class */
    private static final class AlpnStringizer implements SSLStringizer {
        private AlpnStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new AlpnSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/AlpnExtension$CHAlpnProducer.class */
    private static final class CHAlpnProducer implements HandshakeProducer {
        static final int MAX_AP_LENGTH = 255;
        static final int MAX_AP_LIST_LENGTH = 65535;

        private CHAlpnProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.CH_ALPN)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.info("Ignore client unavailable extension: " + SSLExtension.CH_ALPN.name, new Object[0]);
                }
                chc.applicationProtocol = "";
                chc.conContext.applicationProtocol = "";
                return null;
            }
            String[] laps = chc.sslConfig.applicationProtocols;
            if (laps == null || laps.length == 0) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.info("No available application protocols", new Object[0]);
                    return null;
                }
                return null;
            }
            int listLength = 0;
            for (String ap : laps) {
                int length = ap.getBytes(AlpnExtension.alpnCharset).length;
                if (length == 0) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.severe("Application protocol name cannot be empty", new Object[0]);
                    }
                    throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Application protocol name cannot be empty");
                } else if (length <= 255) {
                    listLength += length + 1;
                    if (listLength > 65535) {
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                            SSLLogger.severe("The configured application protocols (" + Arrays.toString(laps) + ") exceed the size limit (65535 bytes)", new Object[0]);
                        }
                        throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "The configured application protocols (" + Arrays.toString(laps) + ") exceed the size limit (65535 bytes)");
                    }
                } else {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.severe("Application protocol name (" + ap + ") exceeds the size limit (255 bytes)", new Object[0]);
                    }
                    throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Application protocol name (" + ap + ") exceeds the size limit (255 bytes)");
                }
            }
            byte[] extData = new byte[listLength + 2];
            ByteBuffer m = ByteBuffer.wrap(extData);
            Record.putInt16(m, listLength);
            for (String ap2 : laps) {
                Record.putBytes8(m, ap2.getBytes(AlpnExtension.alpnCharset));
            }
            chc.handshakeExtensions.put(SSLExtension.CH_ALPN, new AlpnSpec(chc.sslConfig.applicationProtocols));
            return extData;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/AlpnExtension$CHAlpnConsumer.class */
    private static final class CHAlpnConsumer implements SSLExtension.ExtensionConsumer {
        private CHAlpnConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            boolean noAPSelector;
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_ALPN)) {
                shc.applicationProtocol = "";
                shc.conContext.applicationProtocol = "";
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.info("Ignore server unavailable extension: " + SSLExtension.CH_ALPN.name, new Object[0]);
                    return;
                }
                return;
            }
            if (shc.conContext.transport instanceof SSLEngine) {
                noAPSelector = shc.sslConfig.engineAPSelector == null;
            } else {
                noAPSelector = shc.sslConfig.socketAPSelector == null;
            }
            boolean noAlpnProtocols = shc.sslConfig.applicationProtocols == null || shc.sslConfig.applicationProtocols.length == 0;
            if (noAPSelector && noAlpnProtocols) {
                shc.applicationProtocol = "";
                shc.conContext.applicationProtocol = "";
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore server unenabled extension: " + SSLExtension.CH_ALPN.name, new Object[0]);
                    return;
                }
                return;
            }
            try {
                AlpnSpec spec = new AlpnSpec(buffer);
                if (noAPSelector) {
                    List<String> protocolNames = spec.applicationProtocols;
                    boolean matched = false;
                    String[] strArr = shc.sslConfig.applicationProtocols;
                    int length = strArr.length;
                    int i = 0;
                    while (true) {
                        if (i >= length) {
                            break;
                        }
                        String ap = strArr[i];
                        if (!protocolNames.contains(ap)) {
                            i++;
                        } else {
                            shc.applicationProtocol = ap;
                            shc.conContext.applicationProtocol = ap;
                            matched = true;
                            break;
                        }
                    }
                    if (!matched) {
                        throw shc.conContext.fatal(Alert.NO_APPLICATION_PROTOCOL, "No matching application layer protocol values");
                    }
                }
                shc.handshakeExtensions.put(SSLExtension.CH_ALPN, spec);
            } catch (IOException ioe) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/AlpnExtension$CHAlpnAbsence.class */
    private static final class CHAlpnAbsence implements HandshakeAbsence {
        private CHAlpnAbsence() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeAbsence
        public void absent(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            shc.applicationProtocol = "";
            shc.conContext.applicationProtocol = "";
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/AlpnExtension$SHAlpnProducer.class */
    private static final class SHAlpnProducer implements HandshakeProducer {
        private SHAlpnProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            AlpnSpec requestedAlps = (AlpnSpec) shc.handshakeExtensions.get(SSLExtension.CH_ALPN);
            if (requestedAlps == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " + SSLExtension.SH_ALPN.name, new Object[0]);
                }
                shc.applicationProtocol = "";
                shc.conContext.applicationProtocol = "";
                return null;
            }
            List<String> alps = requestedAlps.applicationProtocols;
            if (shc.conContext.transport instanceof SSLEngine) {
                if (shc.sslConfig.engineAPSelector != null) {
                    SSLEngine engine = (SSLEngine) shc.conContext.transport;
                    shc.applicationProtocol = shc.sslConfig.engineAPSelector.apply(engine, alps);
                    if (shc.applicationProtocol == null || (!shc.applicationProtocol.isEmpty() && !alps.contains(shc.applicationProtocol))) {
                        throw shc.conContext.fatal(Alert.NO_APPLICATION_PROTOCOL, "No matching application layer protocol values");
                    }
                }
            } else if (shc.sslConfig.socketAPSelector != null) {
                SSLSocket socket = (SSLSocket) shc.conContext.transport;
                shc.applicationProtocol = shc.sslConfig.socketAPSelector.apply(socket, alps);
                if (shc.applicationProtocol == null || (!shc.applicationProtocol.isEmpty() && !alps.contains(shc.applicationProtocol))) {
                    throw shc.conContext.fatal(Alert.NO_APPLICATION_PROTOCOL, "No matching application layer protocol values");
                }
            }
            if (shc.applicationProtocol == null || shc.applicationProtocol.isEmpty()) {
                shc.applicationProtocol = "";
                shc.conContext.applicationProtocol = "";
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("Ignore, no negotiated application layer protocol", new Object[0]);
                    return null;
                }
                return null;
            }
            byte[] bytes = shc.applicationProtocol.getBytes(AlpnExtension.alpnCharset);
            int listLen = bytes.length + 1;
            byte[] extData = new byte[listLen + 2];
            ByteBuffer m = ByteBuffer.wrap(extData);
            Record.putInt16(m, listLen);
            Record.putBytes8(m, bytes);
            shc.conContext.applicationProtocol = shc.applicationProtocol;
            shc.handshakeExtensions.remove(SSLExtension.CH_ALPN);
            return extData;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/AlpnExtension$SHAlpnConsumer.class */
    private static final class SHAlpnConsumer implements SSLExtension.ExtensionConsumer {
        private SHAlpnConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            AlpnSpec requestedAlps = (AlpnSpec) chc.handshakeExtensions.get(SSLExtension.CH_ALPN);
            if (requestedAlps == null || requestedAlps.applicationProtocols == null || requestedAlps.applicationProtocols.isEmpty()) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected " + SSLExtension.CH_ALPN.name + " extension");
            }
            try {
                AlpnSpec spec = new AlpnSpec(buffer);
                if (spec.applicationProtocols.size() != 1) {
                    throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Invalid " + SSLExtension.CH_ALPN.name + " extension: Only one application protocol name is allowed in ServerHello message");
                }
                if (!requestedAlps.applicationProtocols.containsAll(spec.applicationProtocols)) {
                    throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Invalid " + SSLExtension.CH_ALPN.name + " extension: Only client specified application protocol is allowed in ServerHello message");
                }
                chc.applicationProtocol = spec.applicationProtocols.get(0);
                chc.conContext.applicationProtocol = chc.applicationProtocol;
                chc.handshakeExtensions.remove(SSLExtension.CH_ALPN);
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/AlpnExtension$SHAlpnAbsence.class */
    private static final class SHAlpnAbsence implements HandshakeAbsence {
        private SHAlpnAbsence() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeAbsence
        public void absent(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            chc.applicationProtocol = "";
            chc.conContext.applicationProtocol = "";
        }
    }
}