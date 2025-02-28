package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.CryptoPrimitive;
import java.security.GeneralSecurityException;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.net.ssl.SSLProtocolException;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.openjsse.sun.security.ssl.DHKeyExchange;
import org.openjsse.sun.security.ssl.ECDHKeyExchange;
import org.openjsse.sun.security.ssl.SSLExtension;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.ssl.SupportedGroupsExtension;
import org.openjsse.sun.security.util.HexDumpEncoder;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyShareExtension.class */
final class KeyShareExtension {
    static final HandshakeProducer chNetworkProducer = new CHKeyShareProducer();
    static final SSLExtension.ExtensionConsumer chOnLoadConsumer = new CHKeyShareConsumer();
    static final HandshakeAbsence chOnTradAbsence = new CHKeyShareOnTradeAbsence();
    static final SSLStringizer chStringizer = new CHKeyShareStringizer();
    static final HandshakeProducer shNetworkProducer = new SHKeyShareProducer();
    static final SSLExtension.ExtensionConsumer shOnLoadConsumer = new SHKeyShareConsumer();
    static final HandshakeAbsence shOnLoadAbsence = new SHKeyShareAbsence();
    static final SSLStringizer shStringizer = new SHKeyShareStringizer();
    static final HandshakeProducer hrrNetworkProducer = new HRRKeyShareProducer();
    static final SSLExtension.ExtensionConsumer hrrOnLoadConsumer = new HRRKeyShareConsumer();
    static final HandshakeProducer hrrNetworkReproducer = new HRRKeyShareReproducer();
    static final SSLStringizer hrrStringizer = new HRRKeyShareStringizer();

    KeyShareExtension() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyShareExtension$KeyShareEntry.class */
    public static final class KeyShareEntry {
        final int namedGroupId;
        final byte[] keyExchange;

        private KeyShareEntry(int namedGroupId, byte[] keyExchange) {
            this.namedGroupId = namedGroupId;
            this.keyExchange = keyExchange;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public byte[] getEncoded() {
            byte[] buffer = new byte[this.keyExchange.length + 4];
            ByteBuffer m = ByteBuffer.wrap(buffer);
            try {
                Record.putInt16(m, this.namedGroupId);
                Record.putBytes16(m, this.keyExchange);
            } catch (IOException ioe) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("Unlikely IOException", ioe);
                }
            }
            return buffer;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public int getEncodedSize() {
            return this.keyExchange.length + 4;
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\n'{'\n  \"named group\": {0}\n  \"key_exchange\": '{'\n{1}\n  '}'\n'}',", Locale.ENGLISH);
            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            Object[] messageFields = {SupportedGroupsExtension.NamedGroup.nameOf(this.namedGroupId), Utilities.indent(hexEncoder.encode(this.keyExchange), "    ")};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyShareExtension$CHKeyShareSpec.class */
    static final class CHKeyShareSpec implements SSLExtension.SSLExtensionSpec {
        final List<KeyShareEntry> clientShares;

        private CHKeyShareSpec(List<KeyShareEntry> clientShares) {
            this.clientShares = clientShares;
        }

        private CHKeyShareSpec(ByteBuffer buffer) throws IOException {
            if (buffer.remaining() < 2) {
                throw new SSLProtocolException("Invalid key_share extension: insufficient data (length=" + buffer.remaining() + ")");
            }
            int listLen = Record.getInt16(buffer);
            if (listLen != buffer.remaining()) {
                throw new SSLProtocolException("Invalid key_share extension: incorrect list length (length=" + listLen + ")");
            }
            List<KeyShareEntry> keyShares = new LinkedList<>();
            while (buffer.hasRemaining()) {
                int namedGroupId = Record.getInt16(buffer);
                byte[] keyExchange = Record.getBytes16(buffer);
                if (keyExchange.length == 0) {
                    throw new SSLProtocolException("Invalid key_share extension: empty key_exchange");
                }
                keyShares.add(new KeyShareEntry(namedGroupId, keyExchange));
            }
            this.clientShares = Collections.unmodifiableList(keyShares);
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"client_shares\": '['{0}\n']'", Locale.ENGLISH);
            StringBuilder builder = new StringBuilder(512);
            for (KeyShareEntry entry : this.clientShares) {
                builder.append(entry.toString());
            }
            Object[] messageFields = {Utilities.indent(builder.toString())};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyShareExtension$CHKeyShareStringizer.class */
    private static final class CHKeyShareStringizer implements SSLStringizer {
        private CHKeyShareStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new CHKeyShareSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyShareExtension$CHKeyShareProducer.class */
    private static final class CHKeyShareProducer implements HandshakeProducer {
        private CHKeyShareProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            List<SupportedGroupsExtension.NamedGroup> namedGroups;
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.CH_KEY_SHARE)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable key_share extension", new Object[0]);
                    return null;
                }
                return null;
            }
            if (chc.serverSelectedNamedGroup != null) {
                namedGroups = Arrays.asList(chc.serverSelectedNamedGroup);
            } else {
                namedGroups = chc.clientRequestedNamedGroups;
                if (namedGroups == null || namedGroups.isEmpty()) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.warning("Ignore key_share extension, no supported groups", new Object[0]);
                        return null;
                    }
                    return null;
                }
            }
            List<KeyShareEntry> keyShares = new LinkedList<>();
            for (SupportedGroupsExtension.NamedGroup ng : namedGroups) {
                SSLKeyExchange ke = SSLKeyExchange.valueOf(ng);
                if (ke == null) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.warning("No key exchange for named group " + ng.name, new Object[0]);
                    }
                } else {
                    SSLPossession[] poses = ke.createPossessions(chc);
                    for (SSLPossession pos : poses) {
                        chc.handshakePossessions.add(pos);
                        if ((pos instanceof ECDHKeyExchange.ECDHEPossession) || (pos instanceof DHKeyExchange.DHEPossession)) {
                            keyShares.add(new KeyShareEntry(ng.f1009id, pos.encode()));
                        }
                    }
                    if (!keyShares.isEmpty()) {
                        break;
                    }
                }
            }
            int listLen = 0;
            for (KeyShareEntry entry : keyShares) {
                listLen += entry.getEncodedSize();
            }
            byte[] extData = new byte[listLen + 2];
            ByteBuffer m = ByteBuffer.wrap(extData);
            Record.putInt16(m, listLen);
            for (KeyShareEntry entry2 : keyShares) {
                m.put(entry2.getEncoded());
            }
            chc.handshakeExtensions.put(SSLExtension.CH_KEY_SHARE, new CHKeyShareSpec(keyShares));
            return extData;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyShareExtension$CHKeyShareConsumer.class */
    private static final class CHKeyShareConsumer implements SSLExtension.ExtensionConsumer {
        private CHKeyShareConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (shc.handshakeExtensions.containsKey(SSLExtension.CH_KEY_SHARE)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("The key_share extension has been loaded", new Object[0]);
                }
            } else if (!shc.sslConfig.isAvailable(SSLExtension.CH_KEY_SHARE)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable key_share extension", new Object[0]);
                }
            } else {
                try {
                    CHKeyShareSpec spec = new CHKeyShareSpec(buffer);
                    List<SSLCredentials> credentials = new LinkedList<>();
                    for (KeyShareEntry entry : spec.clientShares) {
                        SupportedGroupsExtension.NamedGroup ng = SupportedGroupsExtension.NamedGroup.valueOf(entry.namedGroupId);
                        if (ng == null || !SupportedGroupsExtension.SupportedGroups.isActivatable(shc.algorithmConstraints, ng)) {
                            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                                SSLLogger.fine("Ignore unsupported named group: " + SupportedGroupsExtension.NamedGroup.nameOf(entry.namedGroupId), new Object[0]);
                            }
                        } else if (ng.type == SupportedGroupsExtension.NamedGroupType.NAMED_GROUP_ECDHE) {
                            try {
                                ECDHKeyExchange.ECDHECredentials ecdhec = ECDHKeyExchange.ECDHECredentials.valueOf(ng, entry.keyExchange);
                                if (ecdhec != null) {
                                    if (!shc.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), ecdhec.popPublicKey)) {
                                        SSLLogger.warning("ECDHE key share entry does not comply to algorithm constraints", new Object[0]);
                                    } else {
                                        credentials.add(ecdhec);
                                    }
                                }
                            } catch (IOException | GeneralSecurityException e) {
                                SSLLogger.warning("Cannot decode named group: " + SupportedGroupsExtension.NamedGroup.nameOf(entry.namedGroupId), new Object[0]);
                            }
                        } else if (ng.type == SupportedGroupsExtension.NamedGroupType.NAMED_GROUP_FFDHE) {
                            try {
                                DHKeyExchange.DHECredentials dhec = DHKeyExchange.DHECredentials.valueOf(ng, entry.keyExchange);
                                if (dhec != null) {
                                    if (!shc.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), dhec.popPublicKey)) {
                                        SSLLogger.warning("DHE key share entry does not comply to algorithm constraints", new Object[0]);
                                    } else {
                                        credentials.add(dhec);
                                    }
                                }
                            } catch (IOException | GeneralSecurityException e2) {
                                SSLLogger.warning("Cannot decode named group: " + SupportedGroupsExtension.NamedGroup.nameOf(entry.namedGroupId), new Object[0]);
                            }
                        }
                    }
                    if (!credentials.isEmpty()) {
                        shc.handshakeCredentials.addAll(credentials);
                    } else {
                        shc.handshakeProducers.put(Byte.valueOf(SSLHandshake.HELLO_RETRY_REQUEST.f987id), SSLHandshake.HELLO_RETRY_REQUEST);
                    }
                    shc.handshakeExtensions.put(SSLExtension.CH_KEY_SHARE, spec);
                } catch (IOException ioe) {
                    throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
                }
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyShareExtension$CHKeyShareOnTradeAbsence.class */
    private static final class CHKeyShareOnTradeAbsence implements HandshakeAbsence {
        private CHKeyShareOnTradeAbsence() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeAbsence
        public void absent(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (shc.negotiatedProtocol.useTLS13PlusSpec() && shc.handshakeExtensions.containsKey(SSLExtension.CH_SUPPORTED_GROUPS)) {
                throw shc.conContext.fatal(Alert.MISSING_EXTENSION, "No key_share extension to work with the supported_groups extension");
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyShareExtension$SHKeyShareSpec.class */
    static final class SHKeyShareSpec implements SSLExtension.SSLExtensionSpec {
        final KeyShareEntry serverShare;

        SHKeyShareSpec(KeyShareEntry serverShare) {
            this.serverShare = serverShare;
        }

        private SHKeyShareSpec(ByteBuffer buffer) throws IOException {
            if (buffer.remaining() < 5) {
                throw new SSLProtocolException("Invalid key_share extension: insufficient data (length=" + buffer.remaining() + ")");
            }
            int namedGroupId = Record.getInt16(buffer);
            byte[] keyExchange = Record.getBytes16(buffer);
            if (buffer.hasRemaining()) {
                throw new SSLProtocolException("Invalid key_share extension: unknown extra data");
            }
            this.serverShare = new KeyShareEntry(namedGroupId, keyExchange);
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"server_share\": '{'\n  \"named group\": {0}\n  \"key_exchange\": '{'\n{1}\n  '}'\n'}',", Locale.ENGLISH);
            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            Object[] messageFields = {SupportedGroupsExtension.NamedGroup.nameOf(this.serverShare.namedGroupId), Utilities.indent(hexEncoder.encode(this.serverShare.keyExchange), "    ")};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyShareExtension$SHKeyShareStringizer.class */
    private static final class SHKeyShareStringizer implements SSLStringizer {
        private SHKeyShareStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new SHKeyShareSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyShareExtension$SHKeyShareProducer.class */
    private static final class SHKeyShareProducer implements HandshakeProducer {
        private SHKeyShareProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            Map.Entry<Byte, HandshakeProducer>[] handshakeProducers;
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            CHKeyShareSpec kss = (CHKeyShareSpec) shc.handshakeExtensions.get(SSLExtension.CH_KEY_SHARE);
            if (kss == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("Ignore, no client key_share extension", new Object[0]);
                    return null;
                }
                return null;
            } else if (!shc.sslConfig.isAvailable(SSLExtension.SH_KEY_SHARE)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("Ignore, no available server key_share extension", new Object[0]);
                    return null;
                }
                return null;
            } else if (shc.handshakeCredentials == null || shc.handshakeCredentials.isEmpty()) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("No available client key share entries", new Object[0]);
                    return null;
                }
                return null;
            } else {
                KeyShareEntry keyShare = null;
                Iterator<SSLCredentials> it = shc.handshakeCredentials.iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    SSLCredentials cd = it.next();
                    SupportedGroupsExtension.NamedGroup ng = null;
                    if (cd instanceof ECDHKeyExchange.ECDHECredentials) {
                        ng = ((ECDHKeyExchange.ECDHECredentials) cd).namedGroup;
                    } else if (cd instanceof DHKeyExchange.DHECredentials) {
                        ng = ((DHKeyExchange.DHECredentials) cd).namedGroup;
                    }
                    if (ng != null) {
                        SSLKeyExchange ke = SSLKeyExchange.valueOf(ng);
                        if (ke == null) {
                            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                                SSLLogger.warning("No key exchange for named group " + ng.name, new Object[0]);
                            }
                        } else {
                            SSLPossession[] poses = ke.createPossessions(shc);
                            for (SSLPossession pos : poses) {
                                if ((pos instanceof ECDHKeyExchange.ECDHEPossession) || (pos instanceof DHKeyExchange.DHEPossession)) {
                                    shc.handshakeKeyExchange = ke;
                                    shc.handshakePossessions.add(pos);
                                    keyShare = new KeyShareEntry(ng.f1009id, pos.encode());
                                    break;
                                }
                            }
                            if (keyShare != null) {
                                for (Map.Entry<Byte, HandshakeProducer> me : ke.getHandshakeProducers(shc)) {
                                    shc.handshakeProducers.put(me.getKey(), me.getValue());
                                }
                            }
                        }
                    }
                }
                if (keyShare != null) {
                    byte[] extData = keyShare.getEncoded();
                    SHKeyShareSpec spec = new SHKeyShareSpec(keyShare);
                    shc.handshakeExtensions.put(SSLExtension.SH_KEY_SHARE, spec);
                    return extData;
                } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("No available server key_share extension", new Object[0]);
                    return null;
                } else {
                    return null;
                }
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyShareExtension$SHKeyShareConsumer.class */
    private static final class SHKeyShareConsumer implements SSLExtension.ExtensionConsumer {
        private SHKeyShareConsumer() {
        }

        /* JADX WARN: Multi-variable type inference failed */
        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (chc.clientRequestedNamedGroups == null || chc.clientRequestedNamedGroups.isEmpty()) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected key_share extension in ServerHello");
            }
            if (!chc.sslConfig.isAvailable(SSLExtension.SH_KEY_SHARE)) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unsupported key_share extension in ServerHello");
            }
            try {
                SHKeyShareSpec spec = new SHKeyShareSpec(buffer);
                KeyShareEntry keyShare = spec.serverShare;
                SupportedGroupsExtension.NamedGroup ng = SupportedGroupsExtension.NamedGroup.valueOf(keyShare.namedGroupId);
                if (ng == null || !SupportedGroupsExtension.SupportedGroups.isActivatable(chc.algorithmConstraints, ng)) {
                    throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unsupported named group: " + SupportedGroupsExtension.NamedGroup.nameOf(keyShare.namedGroupId));
                }
                SSLKeyExchange ke = SSLKeyExchange.valueOf(ng);
                if (ke == null) {
                    throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "No key exchange for named group " + ng.name);
                }
                SSLCredentials credentials = null;
                if (ng.type == SupportedGroupsExtension.NamedGroupType.NAMED_GROUP_ECDHE) {
                    try {
                        ECDHKeyExchange.ECDHECredentials ecdhec = ECDHKeyExchange.ECDHECredentials.valueOf(ng, keyShare.keyExchange);
                        if (ecdhec != null) {
                            if (!chc.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), ecdhec.popPublicKey)) {
                                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "ECDHE key share entry does not comply to algorithm constraints");
                            }
                            credentials = ecdhec;
                        }
                    } catch (IOException | GeneralSecurityException e) {
                        throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Cannot decode named group: " + SupportedGroupsExtension.NamedGroup.nameOf(keyShare.namedGroupId));
                    }
                } else if (ng.type == SupportedGroupsExtension.NamedGroupType.NAMED_GROUP_FFDHE) {
                    try {
                        DHKeyExchange.DHECredentials dhec = DHKeyExchange.DHECredentials.valueOf(ng, keyShare.keyExchange);
                        if (dhec != 0) {
                            if (!chc.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), dhec.popPublicKey)) {
                                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "DHE key share entry does not comply to algorithm constraints");
                            }
                            credentials = dhec;
                        }
                    } catch (IOException | GeneralSecurityException e2) {
                        throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Cannot decode named group: " + SupportedGroupsExtension.NamedGroup.nameOf(keyShare.namedGroupId));
                    }
                } else {
                    throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unsupported named group: " + SupportedGroupsExtension.NamedGroup.nameOf(keyShare.namedGroupId));
                }
                if (credentials == null) {
                    throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unsupported named group: " + ng.name);
                }
                chc.handshakeKeyExchange = ke;
                chc.handshakeCredentials.add(credentials);
                chc.handshakeExtensions.put(SSLExtension.SH_KEY_SHARE, spec);
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyShareExtension$SHKeyShareAbsence.class */
    private static final class SHKeyShareAbsence implements HandshakeAbsence {
        private SHKeyShareAbsence() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeAbsence
        public void absent(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (SSLLogger.isOn && SSLLogger.isOn("handshake")) {
                SSLLogger.fine("No key_share extension in ServerHello, cleanup the key shares if necessary", new Object[0]);
            }
            chc.handshakePossessions.clear();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyShareExtension$HRRKeyShareSpec.class */
    static final class HRRKeyShareSpec implements SSLExtension.SSLExtensionSpec {
        final int selectedGroup;

        HRRKeyShareSpec(SupportedGroupsExtension.NamedGroup serverGroup) {
            this.selectedGroup = serverGroup.f1009id;
        }

        private HRRKeyShareSpec(ByteBuffer buffer) throws IOException {
            if (buffer.remaining() != 2) {
                throw new SSLProtocolException("Invalid key_share extension: improper data (length=" + buffer.remaining() + ")");
            }
            this.selectedGroup = Record.getInt16(buffer);
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"selected group\": '['{0}']'", Locale.ENGLISH);
            Object[] messageFields = {SupportedGroupsExtension.NamedGroup.nameOf(this.selectedGroup)};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyShareExtension$HRRKeyShareStringizer.class */
    private static final class HRRKeyShareStringizer implements SSLStringizer {
        private HRRKeyShareStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new HRRKeyShareSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyShareExtension$HRRKeyShareProducer.class */
    private static final class HRRKeyShareProducer implements HandshakeProducer {
        private HRRKeyShareProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.HRR_KEY_SHARE)) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unsupported key_share extension in HelloRetryRequest");
            }
            if (shc.clientRequestedNamedGroups == null || shc.clientRequestedNamedGroups.isEmpty()) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected key_share extension in HelloRetryRequest");
            }
            SupportedGroupsExtension.NamedGroup selectedGroup = null;
            Iterator<SupportedGroupsExtension.NamedGroup> it = shc.clientRequestedNamedGroups.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                SupportedGroupsExtension.NamedGroup ng = it.next();
                if (SupportedGroupsExtension.SupportedGroups.isActivatable(shc.algorithmConstraints, ng)) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("HelloRetryRequest selected named group: " + ng.name, new Object[0]);
                    }
                    selectedGroup = ng;
                }
            }
            if (selectedGroup == null) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "No common named group");
            }
            byte[] extdata = {(byte) ((selectedGroup.f1009id >> 8) & GF2Field.MASK), (byte) (selectedGroup.f1009id & GF2Field.MASK)};
            shc.serverSelectedNamedGroup = selectedGroup;
            shc.handshakeExtensions.put(SSLExtension.HRR_KEY_SHARE, new HRRKeyShareSpec(selectedGroup));
            return extdata;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyShareExtension$HRRKeyShareReproducer.class */
    private static final class HRRKeyShareReproducer implements HandshakeProducer {
        private HRRKeyShareReproducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.HRR_KEY_SHARE)) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unsupported key_share extension in HelloRetryRequest");
            }
            CHKeyShareSpec spec = (CHKeyShareSpec) shc.handshakeExtensions.get(SSLExtension.CH_KEY_SHARE);
            if (spec != null && spec.clientShares != null && spec.clientShares.size() == 1) {
                int namedGroupId = spec.clientShares.get(0).namedGroupId;
                byte[] extdata = {(byte) ((namedGroupId >> 8) & GF2Field.MASK), (byte) (namedGroupId & GF2Field.MASK)};
                return extdata;
            }
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyShareExtension$HRRKeyShareConsumer.class */
    private static final class HRRKeyShareConsumer implements SSLExtension.ExtensionConsumer {
        private HRRKeyShareConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.HRR_KEY_SHARE)) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unsupported key_share extension in HelloRetryRequest");
            }
            if (chc.clientRequestedNamedGroups == null || chc.clientRequestedNamedGroups.isEmpty()) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected key_share extension in HelloRetryRequest");
            }
            try {
                HRRKeyShareSpec spec = new HRRKeyShareSpec(buffer);
                SupportedGroupsExtension.NamedGroup serverGroup = SupportedGroupsExtension.NamedGroup.valueOf(spec.selectedGroup);
                if (serverGroup == null) {
                    throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unsupported HelloRetryRequest selected group: " + SupportedGroupsExtension.NamedGroup.nameOf(spec.selectedGroup));
                }
                if (!chc.clientRequestedNamedGroups.contains(serverGroup)) {
                    throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected HelloRetryRequest selected group: " + serverGroup.name);
                }
                chc.serverSelectedNamedGroup = serverGroup;
                chc.handshakeExtensions.put(SSLExtension.HRR_KEY_SHARE, spec);
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }
}