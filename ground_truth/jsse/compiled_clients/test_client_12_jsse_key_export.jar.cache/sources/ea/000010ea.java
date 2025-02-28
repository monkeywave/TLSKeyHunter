package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLPeerUnverifiedException;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.openjsse.sun.security.ssl.CipherSuite;
import org.openjsse.sun.security.ssl.ClientHello;
import org.openjsse.sun.security.ssl.SSLExtension;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PreSharedKeyExtension.class */
final class PreSharedKeyExtension {
    static final HandshakeProducer chNetworkProducer = new CHPreSharedKeyProducer();
    static final SSLExtension.ExtensionConsumer chOnLoadConsumer = new CHPreSharedKeyConsumer();
    static final HandshakeAbsence chOnLoadAbsence = new CHPreSharedKeyOnLoadAbsence();
    static final HandshakeConsumer chOnTradeConsumer = new CHPreSharedKeyUpdate();
    static final HandshakeAbsence chOnTradAbsence = new CHPreSharedKeyOnTradeAbsence();
    static final SSLStringizer chStringizer = new CHPreSharedKeyStringizer();
    static final HandshakeProducer shNetworkProducer = new SHPreSharedKeyProducer();
    static final SSLExtension.ExtensionConsumer shOnLoadConsumer = new SHPreSharedKeyConsumer();
    static final HandshakeAbsence shOnLoadAbsence = new SHPreSharedKeyAbsence();
    static final SSLStringizer shStringizer = new SHPreSharedKeyStringizer();

    PreSharedKeyExtension() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PreSharedKeyExtension$PskIdentity.class */
    public static final class PskIdentity {
        final byte[] identity;
        final int obfuscatedAge;

        PskIdentity(byte[] identity, int obfuscatedAge) {
            this.identity = identity;
            this.obfuscatedAge = obfuscatedAge;
        }

        int getEncodedLength() {
            return 2 + this.identity.length + 4;
        }

        void writeEncoded(ByteBuffer m) throws IOException {
            Record.putBytes16(m, this.identity);
            Record.putInt32(m, this.obfuscatedAge);
        }

        public String toString() {
            return "{" + Utilities.toHexString(this.identity) + "," + this.obfuscatedAge + "}";
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PreSharedKeyExtension$CHPreSharedKeySpec.class */
    public static final class CHPreSharedKeySpec implements SSLExtension.SSLExtensionSpec {
        final List<PskIdentity> identities;
        final List<byte[]> binders;

        CHPreSharedKeySpec(List<PskIdentity> identities, List<byte[]> binders) {
            this.identities = identities;
            this.binders = binders;
        }

        CHPreSharedKeySpec(HandshakeContext context, ByteBuffer m) throws IOException {
            if (m.remaining() < 44) {
                throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid pre_shared_key extension: insufficient data (length=" + m.remaining() + ")");
            }
            int idEncodedLength = Record.getInt16(m);
            if (idEncodedLength < 7) {
                throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid pre_shared_key extension: insufficient identities (length=" + idEncodedLength + ")");
            }
            this.identities = new ArrayList();
            int i = 0;
            while (true) {
                int idReadLength = i;
                if (idReadLength < idEncodedLength) {
                    byte[] id = Record.getBytes16(m);
                    if (id.length < 1) {
                        throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid pre_shared_key extension: insufficient identity (length=" + id.length + ")");
                    }
                    int obfuscatedTicketAge = Record.getInt32(m);
                    PskIdentity pskId = new PskIdentity(id, obfuscatedTicketAge);
                    this.identities.add(pskId);
                    i = idReadLength + pskId.getEncodedLength();
                } else if (m.remaining() < 35) {
                    throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid pre_shared_key extension: insufficient binders data (length=" + m.remaining() + ")");
                } else {
                    int bindersEncodedLen = Record.getInt16(m);
                    if (bindersEncodedLen < 33) {
                        throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid pre_shared_key extension: insufficient binders (length=" + bindersEncodedLen + ")");
                    }
                    this.binders = new ArrayList();
                    int i2 = 0;
                    while (true) {
                        int bindersReadLength = i2;
                        if (bindersReadLength < bindersEncodedLen) {
                            byte[] binder = Record.getBytes8(m);
                            if (binder.length < 32) {
                                throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid pre_shared_key extension: insufficient binder entry (length=" + binder.length + ")");
                            }
                            this.binders.add(binder);
                            i2 = bindersReadLength + 1 + binder.length;
                        } else {
                            return;
                        }
                    }
                }
            }
        }

        int getIdsEncodedLength() {
            int idEncodedLength = 0;
            for (PskIdentity curId : this.identities) {
                idEncodedLength += curId.getEncodedLength();
            }
            return idEncodedLength;
        }

        int getBindersEncodedLength() {
            int binderEncodedLength = 0;
            for (byte[] curBinder : this.binders) {
                binderEncodedLength += 1 + curBinder.length;
            }
            return binderEncodedLength;
        }

        byte[] getEncoded() throws IOException {
            int idsEncodedLength = getIdsEncodedLength();
            int bindersEncodedLength = getBindersEncodedLength();
            int encodedLength = 4 + idsEncodedLength + bindersEncodedLength;
            byte[] buffer = new byte[encodedLength];
            ByteBuffer m = ByteBuffer.wrap(buffer);
            Record.putInt16(m, idsEncodedLength);
            for (PskIdentity curId : this.identities) {
                curId.writeEncoded(m);
            }
            Record.putInt16(m, bindersEncodedLength);
            for (byte[] curBinder : this.binders) {
                Record.putBytes8(m, curBinder);
            }
            return buffer;
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"PreSharedKey\": '{'\n  \"identities\"    : \"{0}\",\n  \"binders\"       : \"{1}\",\n'}'", Locale.ENGLISH);
            Object[] messageFields = {Utilities.indent(identitiesString()), Utilities.indent(bindersString())};
            return messageFormat.format(messageFields);
        }

        String identitiesString() {
            StringBuilder result = new StringBuilder();
            for (PskIdentity curId : this.identities) {
                result.append(curId.toString() + "\n");
            }
            return result.toString();
        }

        String bindersString() {
            StringBuilder result = new StringBuilder();
            for (byte[] curBinder : this.binders) {
                result.append("{" + Utilities.toHexString(curBinder) + "}\n");
            }
            return result.toString();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PreSharedKeyExtension$CHPreSharedKeyStringizer.class */
    private static final class CHPreSharedKeyStringizer implements SSLStringizer {
        private CHPreSharedKeyStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new CHPreSharedKeySpec((HandshakeContext) null, buffer).toString();
            } catch (Exception ex) {
                return ex.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PreSharedKeyExtension$SHPreSharedKeySpec.class */
    private static final class SHPreSharedKeySpec implements SSLExtension.SSLExtensionSpec {
        final int selectedIdentity;

        SHPreSharedKeySpec(int selectedIdentity) {
            this.selectedIdentity = selectedIdentity;
        }

        SHPreSharedKeySpec(HandshakeContext context, ByteBuffer m) throws IOException {
            if (m.remaining() < 2) {
                throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid pre_shared_key extension: insufficient selected_identity (length=" + m.remaining() + ")");
            }
            this.selectedIdentity = Record.getInt16(m);
        }

        byte[] getEncoded() throws IOException {
            return new byte[]{(byte) ((this.selectedIdentity >> 8) & GF2Field.MASK), (byte) (this.selectedIdentity & GF2Field.MASK)};
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"PreSharedKey\": '{'\n  \"selected_identity\"      : \"{0}\",\n'}'", Locale.ENGLISH);
            Object[] messageFields = {Utilities.byte16HexString(this.selectedIdentity)};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PreSharedKeyExtension$SHPreSharedKeyStringizer.class */
    private static final class SHPreSharedKeyStringizer implements SSLStringizer {
        private SHPreSharedKeyStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new SHPreSharedKeySpec(null, buffer).toString();
            } catch (Exception ex) {
                return ex.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PreSharedKeyExtension$CHPreSharedKeyConsumer.class */
    private static final class CHPreSharedKeyConsumer implements SSLExtension.ExtensionConsumer {
        private CHPreSharedKeyConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHello.ClientHelloMessage clientHello = (ClientHello.ClientHelloMessage) message;
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_PRE_SHARED_KEY)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable pre_shared_key extension", new Object[0]);
                    return;
                }
                return;
            }
            try {
                CHPreSharedKeySpec pskSpec = new CHPreSharedKeySpec(shc, buffer);
                if (!shc.handshakeExtensions.containsKey(SSLExtension.PSK_KEY_EXCHANGE_MODES)) {
                    throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Client sent PSK but not PSK modes, or the PSK extension is not the last extension");
                }
                if (pskSpec.identities.size() != pskSpec.binders.size()) {
                    throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "PSK extension has incorrect number of binders");
                }
                if (shc.isResumption) {
                    SSLSessionContextImpl sessionCache = (SSLSessionContextImpl) shc.sslContext.engineGetServerSessionContext();
                    int idIndex = 0;
                    Iterator<PskIdentity> it = pskSpec.identities.iterator();
                    while (true) {
                        if (!it.hasNext()) {
                            break;
                        }
                        PskIdentity requestedId = it.next();
                        SSLSessionImpl s = sessionCache.pull(requestedId.identity);
                        if (s != null && PreSharedKeyExtension.canRejoin(clientHello, shc, s)) {
                            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                                SSLLogger.fine("Resuming session: ", s);
                            }
                            shc.resumingSession = s;
                            shc.handshakeExtensions.put(SSLExtension.SH_PRE_SHARED_KEY, new SHPreSharedKeySpec(idIndex));
                        } else {
                            idIndex++;
                        }
                    }
                    if (idIndex == pskSpec.identities.size()) {
                        shc.isResumption = false;
                        shc.resumingSession = null;
                    }
                }
                shc.handshakeExtensions.put(SSLExtension.CH_PRE_SHARED_KEY, pskSpec);
            } catch (IOException ioe) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static boolean canRejoin(ClientHello.ClientHelloMessage clientHello, ServerHandshakeContext shc, SSLSessionImpl s) {
        boolean result = s.isRejoinable() && s.getPreSharedKey() != null;
        if (result && s.getProtocolVersion() != shc.negotiatedProtocol) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                SSLLogger.finest("Can't resume, incorrect protocol version", new Object[0]);
            }
            result = false;
        }
        if (shc.localSupportedSignAlgs == null) {
            shc.localSupportedSignAlgs = SignatureScheme.getSupportedAlgorithms(shc.sslConfig, shc.algorithmConstraints, shc.activeProtocols);
        }
        if (result && shc.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED) {
            try {
                s.getPeerPrincipal();
            } catch (SSLPeerUnverifiedException e) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest("Can't resume, client authentication is required", new Object[0]);
                }
                result = false;
            }
            Collection<SignatureScheme> sessionSigAlgs = s.getLocalSupportedSignatureSchemes();
            if (result && !shc.localSupportedSignAlgs.containsAll(sessionSigAlgs)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Can't resume. Session uses different signature algorithms", new Object[0]);
                }
                result = false;
            }
        }
        String identityAlg = shc.sslConfig.identificationProtocol;
        if (result && identityAlg != null) {
            String sessionIdentityAlg = s.getIdentificationProtocol();
            if (!Objects.equals(identityAlg, sessionIdentityAlg)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest("Can't resume, endpoint id algorithm does not match, requested: " + identityAlg + ", cached: " + sessionIdentityAlg, new Object[0]);
                }
                result = false;
            }
        }
        if (result && (!shc.isNegotiable(s.getSuite()) || !clientHello.cipherSuites.contains(s.getSuite()))) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                SSLLogger.finest("Can't resume, unavailable session cipher suite", new Object[0]);
            }
            result = false;
        }
        return result;
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PreSharedKeyExtension$CHPreSharedKeyUpdate.class */
    private static final class CHPreSharedKeyUpdate implements HandshakeConsumer {
        private CHPreSharedKeyUpdate() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.isResumption || shc.resumingSession == null) {
                return;
            }
            CHPreSharedKeySpec chPsk = (CHPreSharedKeySpec) shc.handshakeExtensions.get(SSLExtension.CH_PRE_SHARED_KEY);
            SHPreSharedKeySpec shPsk = (SHPreSharedKeySpec) shc.handshakeExtensions.get(SSLExtension.SH_PRE_SHARED_KEY);
            if (chPsk == null || shPsk == null) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Required extensions are unavailable");
            }
            byte[] binder = chPsk.binders.get(shPsk.selectedIdentity);
            HandshakeHash pskBinderHash = shc.handshakeHash.copy();
            byte[] lastMessage = pskBinderHash.removeLastReceived();
            ByteBuffer messageBuf = ByteBuffer.wrap(lastMessage);
            messageBuf.position(4);
            ClientHello.ClientHelloMessage.readPartial(shc.conContext, messageBuf);
            int length = messageBuf.position();
            messageBuf.position(0);
            pskBinderHash.receive(messageBuf, length);
            PreSharedKeyExtension.checkBinder(shc, shc.resumingSession, pskBinderHash, binder);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void checkBinder(ServerHandshakeContext shc, SSLSessionImpl session, HandshakeHash pskBinderHash, byte[] binder) throws IOException {
        SecretKey psk = session.getPreSharedKey();
        if (psk == null) {
            throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Session has no PSK");
        }
        SecretKey binderKey = deriveBinderKey(shc, psk, session);
        byte[] computedBinder = computeBinder(shc, binderKey, session, pskBinderHash);
        if (!Arrays.equals(binder, computedBinder)) {
            throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Incorect PSK binder value");
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PreSharedKeyExtension$PartialClientHelloMessage.class */
    public static final class PartialClientHelloMessage extends SSLHandshake.HandshakeMessage {
        private final ClientHello.ClientHelloMessage msg;
        private final CHPreSharedKeySpec psk;

        PartialClientHelloMessage(HandshakeContext ctx, ClientHello.ClientHelloMessage msg, CHPreSharedKeySpec psk) {
            super(ctx);
            this.msg = msg;
            this.psk = psk;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return this.msg.handshakeType();
        }

        private int pskTotalLength() {
            return this.psk.getIdsEncodedLength() + this.psk.getBindersEncodedLength() + 8;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        int messageLength() {
            if (this.msg.extensions.get(SSLExtension.CH_PRE_SHARED_KEY) != null) {
                return this.msg.messageLength();
            }
            return this.msg.messageLength() + pskTotalLength();
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        void send(HandshakeOutStream hos) throws IOException {
            SSLExtension[] values;
            this.msg.sendCore(hos);
            int extsLen = this.msg.extensions.length();
            if (this.msg.extensions.get(SSLExtension.CH_PRE_SHARED_KEY) == null) {
                extsLen += pskTotalLength();
            }
            hos.putInt16(extsLen - 2);
            for (SSLExtension ext : SSLExtension.values()) {
                byte[] extData = this.msg.extensions.get(ext);
                if (extData != null && ext != SSLExtension.CH_PRE_SHARED_KEY) {
                    int extID = ext.f986id;
                    hos.putInt16(extID);
                    hos.putBytes16(extData);
                }
            }
            int extID2 = SSLExtension.CH_PRE_SHARED_KEY.f986id;
            hos.putInt16(extID2);
            byte[] encodedPsk = this.psk.getEncoded();
            hos.putInt16(encodedPsk.length);
            hos.write(encodedPsk, 0, this.psk.getIdsEncodedLength() + 2);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PreSharedKeyExtension$CHPreSharedKeyProducer.class */
    private static final class CHPreSharedKeyProducer implements HandshakeProducer {
        private CHPreSharedKeyProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.isResumption || chc.resumingSession == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("No session to resume.", new Object[0]);
                    return null;
                }
                return null;
            }
            Collection<SignatureScheme> sessionSigAlgs = chc.resumingSession.getLocalSupportedSignatureSchemes();
            if (!chc.localSupportedSignAlgs.containsAll(sessionSigAlgs)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Existing session uses different signature algorithms", new Object[0]);
                    return null;
                }
                return null;
            }
            SecretKey psk = chc.resumingSession.getPreSharedKey();
            if (psk == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Existing session has no PSK.", new Object[0]);
                    return null;
                }
                return null;
            }
            if (chc.pskIdentity == null) {
                chc.pskIdentity = chc.resumingSession.consumePskIdentity();
            }
            if (chc.pskIdentity == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("PSK has no identity, or identity was already used", new Object[0]);
                    return null;
                }
                return null;
            }
            SSLSessionContextImpl sessionCache = (SSLSessionContextImpl) chc.sslContext.engineGetClientSessionContext();
            sessionCache.remove(chc.resumingSession.getSessionId());
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Found resumable session. Preparing PSK message.", new Object[0]);
            }
            List<PskIdentity> identities = new ArrayList<>();
            int ageMillis = (int) (System.currentTimeMillis() - chc.resumingSession.getTicketCreationTime());
            int obfuscatedAge = ageMillis + chc.resumingSession.getTicketAgeAdd();
            identities.add(new PskIdentity(chc.pskIdentity, obfuscatedAge));
            SecretKey binderKey = PreSharedKeyExtension.deriveBinderKey(chc, psk, chc.resumingSession);
            ClientHello.ClientHelloMessage clientHello = (ClientHello.ClientHelloMessage) message;
            CHPreSharedKeySpec pskPrototype = createPskPrototype(chc.resumingSession.getSuite().hashAlg.hashLength, identities);
            HandshakeHash pskBinderHash = chc.handshakeHash.copy();
            byte[] binder = PreSharedKeyExtension.computeBinder(chc, binderKey, pskBinderHash, chc.resumingSession, chc, clientHello, pskPrototype);
            List<byte[]> binders = new ArrayList<>();
            binders.add(binder);
            CHPreSharedKeySpec pskMessage = new CHPreSharedKeySpec(identities, binders);
            chc.handshakeExtensions.put(SSLExtension.CH_PRE_SHARED_KEY, pskMessage);
            return pskMessage.getEncoded();
        }

        private CHPreSharedKeySpec createPskPrototype(int hashLength, List<PskIdentity> identities) {
            List<byte[]> binders = new ArrayList<>();
            byte[] binderProto = new byte[hashLength];
            for (PskIdentity pskIdentity : identities) {
                binders.add(binderProto);
            }
            return new CHPreSharedKeySpec(identities, binders);
        }
    }

    private static byte[] computeBinder(HandshakeContext context, SecretKey binderKey, SSLSessionImpl session, HandshakeHash pskBinderHash) throws IOException {
        pskBinderHash.determine(session.getProtocolVersion(), session.getSuite());
        pskBinderHash.update();
        byte[] digest = pskBinderHash.digest();
        return computeBinder(context, binderKey, session, digest);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static byte[] computeBinder(HandshakeContext context, SecretKey binderKey, HandshakeHash hash, SSLSessionImpl session, HandshakeContext ctx, ClientHello.ClientHelloMessage hello, CHPreSharedKeySpec pskPrototype) throws IOException {
        PartialClientHelloMessage partialMsg = new PartialClientHelloMessage(ctx, hello, pskPrototype);
        SSLEngineOutputRecord record = new SSLEngineOutputRecord(hash);
        HandshakeOutStream hos = new HandshakeOutStream(record);
        partialMsg.write(hos);
        hash.determine(session.getProtocolVersion(), session.getSuite());
        hash.update();
        byte[] digest = hash.digest();
        return computeBinder(context, binderKey, session, digest);
    }

    private static byte[] computeBinder(HandshakeContext context, SecretKey binderKey, SSLSessionImpl session, byte[] digest) throws IOException {
        try {
            CipherSuite.HashAlg hashAlg = session.getSuite().hashAlg;
            HKDF hkdf = new HKDF(hashAlg.name);
            byte[] label = "tls13 finished".getBytes();
            byte[] hkdfInfo = SSLSecretDerivation.createHkdfInfo(label, new byte[0], hashAlg.hashLength);
            SecretKey finishedKey = hkdf.expand(binderKey, hkdfInfo, hashAlg.hashLength, "TlsBinderKey");
            String hmacAlg = "Hmac" + hashAlg.name.replace("-", "");
            try {
                Mac hmac = JsseJce.getMac(hmacAlg);
                hmac.init(finishedKey);
                return hmac.doFinal(digest);
            } catch (InvalidKeyException | NoSuchAlgorithmException ex) {
                throw context.conContext.fatal(Alert.INTERNAL_ERROR, ex);
            }
        } catch (GeneralSecurityException ex2) {
            throw context.conContext.fatal(Alert.INTERNAL_ERROR, ex2);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static SecretKey deriveBinderKey(HandshakeContext context, SecretKey psk, SSLSessionImpl session) throws IOException {
        try {
            CipherSuite.HashAlg hashAlg = session.getSuite().hashAlg;
            HKDF hkdf = new HKDF(hashAlg.name);
            byte[] zeros = new byte[hashAlg.hashLength];
            SecretKey earlySecret = hkdf.extract(zeros, psk, "TlsEarlySecret");
            byte[] label = "tls13 res binder".getBytes();
            MessageDigest md = MessageDigest.getInstance(hashAlg.name);
            byte[] hkdfInfo = SSLSecretDerivation.createHkdfInfo(label, md.digest(new byte[0]), hashAlg.hashLength);
            return hkdf.expand(earlySecret, hkdfInfo, hashAlg.hashLength, "TlsBinderKey");
        } catch (GeneralSecurityException ex) {
            throw context.conContext.fatal(Alert.INTERNAL_ERROR, ex);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PreSharedKeyExtension$CHPreSharedKeyOnLoadAbsence.class */
    private static final class CHPreSharedKeyOnLoadAbsence implements HandshakeAbsence {
        private CHPreSharedKeyOnLoadAbsence() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeAbsence
        public void absent(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Handling pre_shared_key absence.", new Object[0]);
            }
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            shc.resumingSession = null;
            shc.isResumption = false;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PreSharedKeyExtension$CHPreSharedKeyOnTradeAbsence.class */
    private static final class CHPreSharedKeyOnTradeAbsence implements HandshakeAbsence {
        private CHPreSharedKeyOnTradeAbsence() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeAbsence
        public void absent(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (shc.negotiatedProtocol.useTLS13PlusSpec()) {
                if (!shc.handshakeExtensions.containsKey(SSLExtension.CH_SIGNATURE_ALGORITHMS) || !shc.handshakeExtensions.containsKey(SSLExtension.CH_SUPPORTED_GROUPS)) {
                    throw shc.conContext.fatal(Alert.MISSING_EXTENSION, "No supported_groups or signature_algorithms extension when pre_shared_key extension is not present");
                }
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PreSharedKeyExtension$SHPreSharedKeyConsumer.class */
    private static final class SHPreSharedKeyConsumer implements SSLExtension.ExtensionConsumer {
        private SHPreSharedKeyConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.handshakeExtensions.containsKey(SSLExtension.CH_PRE_SHARED_KEY)) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Server sent unexpected pre_shared_key extension");
            }
            SHPreSharedKeySpec shPsk = new SHPreSharedKeySpec(chc, buffer);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Received pre_shared_key extension: ", shPsk);
            }
            if (shPsk.selectedIdentity != 0) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Selected identity index is not in correct range.");
            }
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Resuming session: ", chc.resumingSession);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PreSharedKeyExtension$SHPreSharedKeyAbsence.class */
    private static final class SHPreSharedKeyAbsence implements HandshakeAbsence {
        private SHPreSharedKeyAbsence() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeAbsence
        public void absent(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Handling pre_shared_key absence.", new Object[0]);
            }
            chc.resumingSession = null;
            chc.isResumption = false;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PreSharedKeyExtension$SHPreSharedKeyProducer.class */
    private static final class SHPreSharedKeyProducer implements HandshakeProducer {
        private SHPreSharedKeyProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            SHPreSharedKeySpec psk = (SHPreSharedKeySpec) shc.handshakeExtensions.get(SSLExtension.SH_PRE_SHARED_KEY);
            if (psk == null) {
                return null;
            }
            return psk.getEncoded();
        }
    }
}