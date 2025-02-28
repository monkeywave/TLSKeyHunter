package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLProtocolException;
import org.openjsse.sun.security.ssl.SSLExtension;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerNameExtension.class */
final class ServerNameExtension {
    static final HandshakeProducer chNetworkProducer = new CHServerNameProducer();
    static final SSLExtension.ExtensionConsumer chOnLoadConsumer = new CHServerNameConsumer();
    static final SSLStringizer chStringizer = new CHServerNamesStringizer();
    static final HandshakeProducer shNetworkProducer = new SHServerNameProducer();
    static final SSLExtension.ExtensionConsumer shOnLoadConsumer = new SHServerNameConsumer();
    static final SSLStringizer shStringizer = new SHServerNamesStringizer();
    static final HandshakeProducer eeNetworkProducer = new EEServerNameProducer();
    static final SSLExtension.ExtensionConsumer eeOnLoadConsumer = new EEServerNameConsumer();

    ServerNameExtension() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerNameExtension$CHServerNamesSpec.class */
    static final class CHServerNamesSpec implements SSLExtension.SSLExtensionSpec {
        static final int NAME_HEADER_LENGTH = 3;
        final List<SNIServerName> serverNames;

        private CHServerNamesSpec(List<SNIServerName> serverNames) {
            this.serverNames = Collections.unmodifiableList(new ArrayList(serverNames));
        }

        /* JADX WARN: Multi-variable type inference failed */
        private CHServerNamesSpec(ByteBuffer buffer) throws IOException {
            SNIServerName serverName;
            if (buffer.remaining() < 2) {
                throw new SSLProtocolException("Invalid server_name extension: insufficient data");
            }
            int sniLen = Record.getInt16(buffer);
            if (sniLen == 0 || sniLen != buffer.remaining()) {
                throw new SSLProtocolException("Invalid server_name extension: incomplete data");
            }
            Map<Integer, SNIServerName> sniMap = new LinkedHashMap<>();
            while (buffer.hasRemaining()) {
                int nameType = Record.getInt8(buffer);
                byte[] encoded = Record.getBytes16(buffer);
                if (nameType == 0) {
                    if (encoded.length == 0) {
                        throw new SSLProtocolException("Empty HostName in server_name extension");
                    }
                    try {
                        serverName = new SNIHostName(encoded);
                    } catch (IllegalArgumentException iae) {
                        SSLProtocolException spe = new SSLProtocolException("Illegal server name, type=host_name(" + nameType + "), name=" + new String(encoded, StandardCharsets.UTF_8) + ", value={" + Utilities.toHexString(encoded) + "}");
                        throw ((SSLProtocolException) spe.initCause(iae));
                    }
                } else {
                    try {
                        serverName = new UnknownServerName(nameType, encoded);
                    } catch (IllegalArgumentException iae2) {
                        SSLProtocolException spe2 = new SSLProtocolException("Illegal server name, type=(" + nameType + "), value={" + Utilities.toHexString(encoded) + "}");
                        throw ((SSLProtocolException) spe2.initCause(iae2));
                    }
                }
                if (sniMap.put(Integer.valueOf(serverName.getType()), serverName) != null) {
                    throw new SSLProtocolException("Duplicated server name of type " + serverName.getType());
                }
            }
            this.serverNames = new ArrayList(sniMap.values());
        }

        public String toString() {
            if (this.serverNames == null || this.serverNames.isEmpty()) {
                return "<no server name indicator specified>";
            }
            StringBuilder builder = new StringBuilder(512);
            for (SNIServerName sn : this.serverNames) {
                builder.append(sn.toString());
                builder.append("\n");
            }
            return builder.toString();
        }

        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerNameExtension$CHServerNamesSpec$UnknownServerName.class */
        private static class UnknownServerName extends SNIServerName {
            UnknownServerName(int code, byte[] encoded) {
                super(code, encoded);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerNameExtension$CHServerNamesStringizer.class */
    private static final class CHServerNamesStringizer implements SSLStringizer {
        private CHServerNamesStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new CHServerNamesSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerNameExtension$CHServerNameProducer.class */
    private static final class CHServerNameProducer implements HandshakeProducer {
        private CHServerNameProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            List<SNIServerName> serverNames;
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.CH_SERVER_NAME)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("Ignore unavailable server_name extension", new Object[0]);
                    return null;
                }
                return null;
            }
            if (chc.isResumption && chc.resumingSession != null) {
                serverNames = chc.resumingSession.getRequestedServerNames();
            } else {
                serverNames = chc.sslConfig.serverNames;
            }
            if (serverNames != null && !serverNames.isEmpty()) {
                int sniLen = 0;
                for (SNIServerName sniName : serverNames) {
                    sniLen = sniLen + 3 + sniName.getEncoded().length;
                }
                byte[] extData = new byte[sniLen + 2];
                ByteBuffer m = ByteBuffer.wrap(extData);
                Record.putInt16(m, sniLen);
                for (SNIServerName sniName2 : serverNames) {
                    Record.putInt8(m, sniName2.getType());
                    Record.putBytes16(m, sniName2.getEncoded());
                }
                chc.requestedServerNames = serverNames;
                chc.handshakeExtensions.put(SSLExtension.CH_SERVER_NAME, new CHServerNamesSpec(serverNames));
                return extData;
            } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.warning("Unable to indicate server name", new Object[0]);
                return null;
            } else {
                return null;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerNameExtension$CHServerNameConsumer.class */
    private static final class CHServerNameConsumer implements SSLExtension.ExtensionConsumer {
        private CHServerNameConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_SERVER_NAME)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " + SSLExtension.CH_SERVER_NAME.name, new Object[0]);
                    return;
                }
                return;
            }
            try {
                CHServerNamesSpec spec = new CHServerNamesSpec(buffer);
                shc.handshakeExtensions.put(SSLExtension.CH_SERVER_NAME, spec);
                SNIServerName sni = null;
                if (!shc.sslConfig.sniMatchers.isEmpty()) {
                    sni = chooseSni(shc.sslConfig.sniMatchers, spec.serverNames);
                    if (sni != null) {
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                            SSLLogger.fine("server name indication (" + sni + ") is accepted", new Object[0]);
                        }
                    } else {
                        throw shc.conContext.fatal(Alert.UNRECOGNIZED_NAME, "Unrecognized server name indication");
                    }
                } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("no server name matchers, ignore server name indication", new Object[0]);
                }
                if (shc.isResumption && shc.resumingSession != null && !Objects.equals(sni, shc.resumingSession.serverNameIndication)) {
                    shc.isResumption = false;
                    shc.resumingSession = null;
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("abort session resumption, different server name indication used", new Object[0]);
                    }
                }
                shc.requestedServerNames = spec.serverNames;
                shc.negotiatedServerName = sni;
            } catch (IOException ioe) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }

        private static SNIServerName chooseSni(Collection<SNIMatcher> matchers, List<SNIServerName> sniNames) {
            if (sniNames != null && !sniNames.isEmpty()) {
                for (SNIMatcher matcher : matchers) {
                    int matcherType = matcher.getType();
                    Iterator<SNIServerName> it = sniNames.iterator();
                    while (true) {
                        if (it.hasNext()) {
                            SNIServerName sniName = it.next();
                            if (sniName.getType() == matcherType) {
                                if (matcher.matches(sniName)) {
                                    return sniName;
                                }
                            }
                        }
                    }
                }
                return null;
            }
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerNameExtension$SHServerNamesSpec.class */
    static final class SHServerNamesSpec implements SSLExtension.SSLExtensionSpec {
        static final SHServerNamesSpec DEFAULT = new SHServerNamesSpec();

        private SHServerNamesSpec() {
        }

        private SHServerNamesSpec(ByteBuffer buffer) throws IOException {
            if (buffer.remaining() != 0) {
                throw new SSLProtocolException("Invalid ServerHello server_name extension: not empty");
            }
        }

        public String toString() {
            return "<empty extension_data field>";
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerNameExtension$SHServerNamesStringizer.class */
    private static final class SHServerNamesStringizer implements SSLStringizer {
        private SHServerNamesStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new SHServerNamesSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerNameExtension$SHServerNameProducer.class */
    private static final class SHServerNameProducer implements HandshakeProducer {
        private SHServerNameProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            CHServerNamesSpec spec = (CHServerNamesSpec) shc.handshakeExtensions.get(SSLExtension.CH_SERVER_NAME);
            if (spec == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("Ignore unavailable extension: " + SSLExtension.SH_SERVER_NAME.name, new Object[0]);
                    return null;
                }
                return null;
            } else if (shc.isResumption || shc.negotiatedServerName == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("No expected server name indication response", new Object[0]);
                    return null;
                }
                return null;
            } else {
                shc.handshakeExtensions.put(SSLExtension.SH_SERVER_NAME, SHServerNamesSpec.DEFAULT);
                return new byte[0];
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerNameExtension$SHServerNameConsumer.class */
    private static final class SHServerNameConsumer implements SSLExtension.ExtensionConsumer {
        private SHServerNameConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            CHServerNamesSpec spec = (CHServerNamesSpec) chc.handshakeExtensions.get(SSLExtension.CH_SERVER_NAME);
            if (spec == null) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected ServerHello server_name extension");
            }
            if (buffer.remaining() != 0) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Invalid ServerHello server_name extension");
            }
            chc.handshakeExtensions.put(SSLExtension.SH_SERVER_NAME, SHServerNamesSpec.DEFAULT);
            chc.negotiatedServerName = spec.serverNames.get(0);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerNameExtension$EEServerNameProducer.class */
    private static final class EEServerNameProducer implements HandshakeProducer {
        private EEServerNameProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            CHServerNamesSpec spec = (CHServerNamesSpec) shc.handshakeExtensions.get(SSLExtension.CH_SERVER_NAME);
            if (spec == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("Ignore unavailable extension: " + SSLExtension.EE_SERVER_NAME.name, new Object[0]);
                    return null;
                }
                return null;
            } else if (shc.isResumption || shc.negotiatedServerName == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("No expected server name indication response", new Object[0]);
                    return null;
                }
                return null;
            } else {
                shc.handshakeExtensions.put(SSLExtension.EE_SERVER_NAME, SHServerNamesSpec.DEFAULT);
                return new byte[0];
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerNameExtension$EEServerNameConsumer.class */
    private static final class EEServerNameConsumer implements SSLExtension.ExtensionConsumer {
        private EEServerNameConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            CHServerNamesSpec spec = (CHServerNamesSpec) chc.handshakeExtensions.get(SSLExtension.CH_SERVER_NAME);
            if (spec == null) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected EncryptedExtensions server_name extension");
            }
            if (buffer.remaining() != 0) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Invalid EncryptedExtensions server_name extension");
            }
            chc.handshakeExtensions.put(SSLExtension.EE_SERVER_NAME, SHServerNamesSpec.DEFAULT);
            chc.negotiatedServerName = spec.serverNames.get(0);
        }
    }
}