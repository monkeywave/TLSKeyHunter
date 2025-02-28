package org.openjsse.sun.security.ssl;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.AbstractMap;
import java.util.Map;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;
import org.openjsse.javax.net.ssl.SSLEngine;
import org.openjsse.sun.security.ssl.SupportedGroupsExtension;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/X509Authentication.class */
public enum X509Authentication implements SSLAuthentication {
    RSA("RSA", new X509PossessionGenerator(new String[]{"RSA"})),
    RSASSA_PSS("RSASSA-PSS", new X509PossessionGenerator(new String[]{"RSASSA-PSS"})),
    RSA_OR_PSS("RSA_OR_PSS", new X509PossessionGenerator(new String[]{"RSA", "RSASSA-PSS"})),
    DSA("DSA", new X509PossessionGenerator(new String[]{"DSA"})),
    EC("EC", new X509PossessionGenerator(new String[]{"EC"}));
    
    final String keyType;
    final SSLPossessionGenerator possessionGenerator;

    X509Authentication(String keyType, SSLPossessionGenerator possessionGenerator) {
        this.keyType = keyType;
        this.possessionGenerator = possessionGenerator;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static X509Authentication valueOf(SignatureScheme signatureScheme) {
        X509Authentication[] values;
        for (X509Authentication au : values()) {
            if (au.keyType.equals(signatureScheme.keyAlgorithm)) {
                return au;
            }
        }
        return null;
    }

    @Override // org.openjsse.sun.security.ssl.SSLPossessionGenerator
    public SSLPossession createPossession(HandshakeContext handshakeContext) {
        return this.possessionGenerator.createPossession(handshakeContext);
    }

    @Override // org.openjsse.sun.security.ssl.SSLHandshakeBinding
    public SSLHandshake[] getRelatedHandshakers(HandshakeContext handshakeContext) {
        return !handshakeContext.negotiatedProtocol.useTLS13PlusSpec() ? new SSLHandshake[]{SSLHandshake.CERTIFICATE, SSLHandshake.CERTIFICATE_REQUEST} : new SSLHandshake[0];
    }

    @Override // org.openjsse.sun.security.ssl.SSLHandshakeBinding
    public Map.Entry<Byte, HandshakeProducer>[] getHandshakeProducers(HandshakeContext handshakeContext) {
        return !handshakeContext.negotiatedProtocol.useTLS13PlusSpec() ? new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(Byte.valueOf(SSLHandshake.CERTIFICATE.f987id), SSLHandshake.CERTIFICATE)} : new Map.Entry[0];
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/X509Authentication$X509Possession.class */
    public static final class X509Possession implements SSLPossession {
        final X509Certificate[] popCerts;
        final PrivateKey popPrivateKey;

        /* JADX INFO: Access modifiers changed from: package-private */
        public X509Possession(PrivateKey popPrivateKey, X509Certificate[] popCerts) {
            this.popCerts = popCerts;
            this.popPrivateKey = popPrivateKey;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public ECParameterSpec getECParameterSpec() {
            if (this.popPrivateKey == null || !"EC".equals(this.popPrivateKey.getAlgorithm())) {
                return null;
            }
            if (this.popPrivateKey instanceof ECKey) {
                return ((ECKey) this.popPrivateKey).getParams();
            }
            if (this.popCerts != null && this.popCerts.length != 0) {
                PublicKey publicKey = this.popCerts[0].getPublicKey();
                if (publicKey instanceof ECKey) {
                    return ((ECKey) publicKey).getParams();
                }
                return null;
            }
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/X509Authentication$X509Credentials.class */
    public static final class X509Credentials implements SSLCredentials {
        final X509Certificate[] popCerts;
        final PublicKey popPublicKey;

        /* JADX INFO: Access modifiers changed from: package-private */
        public X509Credentials(PublicKey popPublicKey, X509Certificate[] popCerts) {
            this.popCerts = popCerts;
            this.popPublicKey = popPublicKey;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/X509Authentication$X509PossessionGenerator.class */
    private static final class X509PossessionGenerator implements SSLPossessionGenerator {
        private final String[] keyTypes;

        private X509PossessionGenerator(String[] keyTypes) {
            this.keyTypes = keyTypes;
        }

        @Override // org.openjsse.sun.security.ssl.SSLPossessionGenerator
        public SSLPossession createPossession(HandshakeContext context) {
            String[] strArr;
            String[] strArr2;
            if (context.sslConfig.isClientMode) {
                for (String keyType : this.keyTypes) {
                    SSLPossession poss = createClientPossession((ClientHandshakeContext) context, keyType);
                    if (poss != null) {
                        return poss;
                    }
                }
                return null;
            }
            for (String keyType2 : this.keyTypes) {
                SSLPossession poss2 = createServerPossession((ServerHandshakeContext) context, keyType2);
                if (poss2 != null) {
                    return poss2;
                }
            }
            return null;
        }

        private SSLPossession createClientPossession(ClientHandshakeContext chc, String keyType) {
            X509ExtendedKeyManager km = chc.sslContext.getX509KeyManager();
            String clientAlias = null;
            if (chc.conContext.transport instanceof SSLSocketImpl) {
                clientAlias = km.chooseClientAlias(new String[]{keyType}, chc.peerSupportedAuthorities, (SSLSocket) chc.conContext.transport);
            } else if (chc.conContext.transport instanceof SSLEngineImpl) {
                clientAlias = km.chooseEngineClientAlias(new String[]{keyType}, chc.peerSupportedAuthorities, (SSLEngine) chc.conContext.transport);
            }
            if (clientAlias == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.finest("No X.509 cert selected for " + keyType, new Object[0]);
                    return null;
                }
                return null;
            }
            PrivateKey clientPrivateKey = km.getPrivateKey(clientAlias);
            if (clientPrivateKey == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.finest(clientAlias + " is not a private key entry", new Object[0]);
                    return null;
                }
                return null;
            }
            X509Certificate[] clientCerts = km.getCertificateChain(clientAlias);
            if (clientCerts == null || clientCerts.length == 0) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.finest(clientAlias + " is a private key entry with no cert chain stored", new Object[0]);
                    return null;
                }
                return null;
            }
            PublicKey clientPublicKey = clientCerts[0].getPublicKey();
            if (!clientPrivateKey.getAlgorithm().equals(keyType) || !clientPublicKey.getAlgorithm().equals(keyType)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.fine(clientAlias + " private or public key is not of " + keyType + " algorithm", new Object[0]);
                    return null;
                }
                return null;
            }
            return new X509Possession(clientPrivateKey, clientCerts);
        }

        private SSLPossession createServerPossession(ServerHandshakeContext shc, String keyType) {
            X509ExtendedKeyManager km = shc.sslContext.getX509KeyManager();
            String serverAlias = null;
            if (shc.conContext.transport instanceof SSLSocketImpl) {
                serverAlias = km.chooseServerAlias(keyType, null, (SSLSocket) shc.conContext.transport);
            } else if (shc.conContext.transport instanceof SSLEngineImpl) {
                serverAlias = km.chooseEngineServerAlias(keyType, null, (SSLEngine) shc.conContext.transport);
            }
            if (serverAlias == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.finest("No X.509 cert selected for " + keyType, new Object[0]);
                    return null;
                }
                return null;
            }
            PrivateKey serverPrivateKey = km.getPrivateKey(serverAlias);
            if (serverPrivateKey == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.finest(serverAlias + " is not a private key entry", new Object[0]);
                    return null;
                }
                return null;
            }
            X509Certificate[] serverCerts = km.getCertificateChain(serverAlias);
            if (serverCerts == null || serverCerts.length == 0) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.finest(serverAlias + " is not a certificate entry", new Object[0]);
                    return null;
                }
                return null;
            }
            PublicKey serverPublicKey = serverCerts[0].getPublicKey();
            if (!serverPrivateKey.getAlgorithm().equals(keyType) || !serverPublicKey.getAlgorithm().equals(keyType)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.fine(serverAlias + " private or public key is not of " + keyType + " algorithm", new Object[0]);
                    return null;
                }
                return null;
            }
            if (keyType.equals("EC")) {
                if (!(serverPublicKey instanceof ECPublicKey)) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                        SSLLogger.warning(serverAlias + " public key is not an instance of ECPublicKey", new Object[0]);
                        return null;
                    }
                    return null;
                }
                ECParameterSpec params = ((ECPublicKey) serverPublicKey).getParams();
                SupportedGroupsExtension.NamedGroup namedGroup = SupportedGroupsExtension.NamedGroup.valueOf(params);
                if (namedGroup == null || !SupportedGroupsExtension.SupportedGroups.isSupported(namedGroup) || (shc.clientRequestedNamedGroups != null && !shc.clientRequestedNamedGroups.contains(namedGroup))) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                        SSLLogger.warning("Unsupported named group (" + namedGroup + ") used in the " + serverAlias + " certificate", new Object[0]);
                        return null;
                    }
                    return null;
                }
            }
            return new X509Possession(serverPrivateKey, serverCerts);
        }
    }
}