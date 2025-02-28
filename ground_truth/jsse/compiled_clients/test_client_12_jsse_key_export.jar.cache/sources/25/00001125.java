package org.openjsse.sun.security.ssl;

import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.util.Set;
import javax.net.ssl.SSLEngine;
import org.openjsse.javax.net.ssl.SSLSocket;
import sun.security.util.DisabledAlgorithmConstraints;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLAlgorithmConstraints.class */
final class SSLAlgorithmConstraints implements AlgorithmConstraints {
    private final AlgorithmConstraints userSpecifiedConstraints;
    private final AlgorithmConstraints peerSpecifiedConstraints;
    private final boolean enabledX509DisabledAlgConstraints;
    private static final AlgorithmConstraints tlsDisabledAlgConstraints = new DisabledAlgorithmConstraints("jdk.tls.disabledAlgorithms", new SSLAlgorithmDecomposer());
    private static final AlgorithmConstraints x509DisabledAlgConstraints = new DisabledAlgorithmConstraints("jdk.certpath.disabledAlgorithms", new SSLAlgorithmDecomposer(true));
    static final AlgorithmConstraints DEFAULT = new SSLAlgorithmConstraints(null);
    static final AlgorithmConstraints DEFAULT_SSL_ONLY = new SSLAlgorithmConstraints((SSLSocket) null, false);

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLAlgorithmConstraints(AlgorithmConstraints userSpecifiedConstraints) {
        this.userSpecifiedConstraints = userSpecifiedConstraints;
        this.peerSpecifiedConstraints = null;
        this.enabledX509DisabledAlgConstraints = true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLAlgorithmConstraints(SSLSocket socket, boolean withDefaultCertPathConstraints) {
        this.userSpecifiedConstraints = getUserSpecifiedConstraints(socket);
        this.peerSpecifiedConstraints = null;
        this.enabledX509DisabledAlgConstraints = withDefaultCertPathConstraints;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLAlgorithmConstraints(SSLEngine engine, boolean withDefaultCertPathConstraints) {
        this.userSpecifiedConstraints = getUserSpecifiedConstraints(engine);
        this.peerSpecifiedConstraints = null;
        this.enabledX509DisabledAlgConstraints = withDefaultCertPathConstraints;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLAlgorithmConstraints(SSLSocket socket, String[] supportedAlgorithms, boolean withDefaultCertPathConstraints) {
        this.userSpecifiedConstraints = getUserSpecifiedConstraints(socket);
        this.peerSpecifiedConstraints = new SupportedSignatureAlgorithmConstraints(supportedAlgorithms);
        this.enabledX509DisabledAlgConstraints = withDefaultCertPathConstraints;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLAlgorithmConstraints(SSLEngine engine, String[] supportedAlgorithms, boolean withDefaultCertPathConstraints) {
        this.userSpecifiedConstraints = getUserSpecifiedConstraints(engine);
        this.peerSpecifiedConstraints = new SupportedSignatureAlgorithmConstraints(supportedAlgorithms);
        this.enabledX509DisabledAlgConstraints = withDefaultCertPathConstraints;
    }

    private static AlgorithmConstraints getUserSpecifiedConstraints(SSLEngine engine) {
        HandshakeContext hc;
        if (engine != null) {
            if ((engine instanceof SSLEngineImpl) && (hc = ((SSLEngineImpl) engine).conContext.handshakeContext) != null) {
                return hc.sslConfig.userSpecifiedAlgorithmConstraints;
            }
            return engine.getSSLParameters().getAlgorithmConstraints();
        }
        return null;
    }

    private static AlgorithmConstraints getUserSpecifiedConstraints(SSLSocket socket) {
        HandshakeContext hc;
        if (socket != null) {
            if ((socket instanceof SSLSocketImpl) && (hc = ((SSLSocketImpl) socket).conContext.handshakeContext) != null) {
                return hc.sslConfig.userSpecifiedAlgorithmConstraints;
            }
            return socket.getSSLParameters().getAlgorithmConstraints();
        }
        return null;
    }

    @Override // java.security.AlgorithmConstraints
    public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters) {
        boolean permitted = true;
        if (this.peerSpecifiedConstraints != null) {
            permitted = this.peerSpecifiedConstraints.permits(primitives, algorithm, parameters);
        }
        if (permitted && this.userSpecifiedConstraints != null) {
            permitted = this.userSpecifiedConstraints.permits(primitives, algorithm, parameters);
        }
        if (permitted) {
            permitted = tlsDisabledAlgConstraints.permits(primitives, algorithm, parameters);
        }
        if (permitted && this.enabledX509DisabledAlgConstraints) {
            permitted = x509DisabledAlgConstraints.permits(primitives, algorithm, parameters);
        }
        return permitted;
    }

    @Override // java.security.AlgorithmConstraints
    public boolean permits(Set<CryptoPrimitive> primitives, Key key) {
        boolean permitted = true;
        if (this.peerSpecifiedConstraints != null) {
            permitted = this.peerSpecifiedConstraints.permits(primitives, key);
        }
        if (permitted && this.userSpecifiedConstraints != null) {
            permitted = this.userSpecifiedConstraints.permits(primitives, key);
        }
        if (permitted) {
            permitted = tlsDisabledAlgConstraints.permits(primitives, key);
        }
        if (permitted && this.enabledX509DisabledAlgConstraints) {
            permitted = x509DisabledAlgConstraints.permits(primitives, key);
        }
        return permitted;
    }

    @Override // java.security.AlgorithmConstraints
    public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters) {
        boolean permitted = true;
        if (this.peerSpecifiedConstraints != null) {
            permitted = this.peerSpecifiedConstraints.permits(primitives, algorithm, key, parameters);
        }
        if (permitted && this.userSpecifiedConstraints != null) {
            permitted = this.userSpecifiedConstraints.permits(primitives, algorithm, key, parameters);
        }
        if (permitted) {
            permitted = tlsDisabledAlgConstraints.permits(primitives, algorithm, key, parameters);
        }
        if (permitted && this.enabledX509DisabledAlgConstraints) {
            permitted = x509DisabledAlgConstraints.permits(primitives, algorithm, key, parameters);
        }
        return permitted;
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLAlgorithmConstraints$SupportedSignatureAlgorithmConstraints.class */
    private static class SupportedSignatureAlgorithmConstraints implements AlgorithmConstraints {
        private String[] supportedAlgorithms;

        SupportedSignatureAlgorithmConstraints(String[] supportedAlgorithms) {
            if (supportedAlgorithms != null) {
                this.supportedAlgorithms = (String[]) supportedAlgorithms.clone();
            } else {
                this.supportedAlgorithms = null;
            }
        }

        @Override // java.security.AlgorithmConstraints
        public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters) {
            String[] strArr;
            if (algorithm == null || algorithm.length() == 0) {
                throw new IllegalArgumentException("No algorithm name specified");
            }
            if (primitives == null || primitives.isEmpty()) {
                throw new IllegalArgumentException("No cryptographic primitive specified");
            }
            if (this.supportedAlgorithms == null || this.supportedAlgorithms.length == 0) {
                return false;
            }
            int position = algorithm.indexOf("and");
            if (position > 0) {
                algorithm = algorithm.substring(0, position);
            }
            for (String supportedAlgorithm : this.supportedAlgorithms) {
                if (algorithm.equalsIgnoreCase(supportedAlgorithm)) {
                    return true;
                }
            }
            return false;
        }

        @Override // java.security.AlgorithmConstraints
        public final boolean permits(Set<CryptoPrimitive> primitives, Key key) {
            return true;
        }

        @Override // java.security.AlgorithmConstraints
        public final boolean permits(Set<CryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters) {
            if (algorithm == null || algorithm.length() == 0) {
                throw new IllegalArgumentException("No algorithm name specified");
            }
            return permits(primitives, algorithm, parameters);
        }
    }
}