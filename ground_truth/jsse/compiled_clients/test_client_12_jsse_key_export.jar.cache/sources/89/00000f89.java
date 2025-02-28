package org.openjsse.sun.security.internal.spec;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

@Deprecated
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/internal/spec/TlsRsaPremasterSecretParameterSpec.class */
public class TlsRsaPremasterSecretParameterSpec implements AlgorithmParameterSpec {
    private final byte[] encodedSecret;
    private static final String PROP_NAME = "com.sun.net.ssl.rsaPreMasterSecretFix";
    private static final boolean rsaPreMasterSecretFix = ((Boolean) AccessController.doPrivileged(new PrivilegedAction<Boolean>() { // from class: org.openjsse.sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // java.security.PrivilegedAction
        public Boolean run() {
            String value = System.getProperty(TlsRsaPremasterSecretParameterSpec.PROP_NAME);
            if (value != null && value.equalsIgnoreCase("true")) {
                return Boolean.TRUE;
            }
            return Boolean.FALSE;
        }
    })).booleanValue();
    private final int clientVersion;
    private final int serverVersion;

    public TlsRsaPremasterSecretParameterSpec(int clientVersion, int serverVersion) {
        this.clientVersion = checkVersion(clientVersion);
        this.serverVersion = checkVersion(serverVersion);
        this.encodedSecret = null;
    }

    public TlsRsaPremasterSecretParameterSpec(int clientVersion, int serverVersion, byte[] encodedSecret) {
        this.clientVersion = checkVersion(clientVersion);
        this.serverVersion = checkVersion(serverVersion);
        if (encodedSecret == null || encodedSecret.length != 48) {
            throw new IllegalArgumentException("Encoded secret is not exactly 48 bytes");
        }
        this.encodedSecret = (byte[]) encodedSecret.clone();
    }

    public int getClientVersion() {
        return this.clientVersion;
    }

    public int getServerVersion() {
        return this.serverVersion;
    }

    public int getMajorVersion() {
        if (rsaPreMasterSecretFix || this.clientVersion >= 770) {
            return (this.clientVersion >>> 8) & GF2Field.MASK;
        }
        return (this.serverVersion >>> 8) & GF2Field.MASK;
    }

    public int getMinorVersion() {
        if (rsaPreMasterSecretFix || this.clientVersion >= 770) {
            return this.clientVersion & GF2Field.MASK;
        }
        return this.serverVersion & GF2Field.MASK;
    }

    private int checkVersion(int version) {
        if (version < 0 || version > 65535) {
            throw new IllegalArgumentException("Version must be between 0 and 65,535");
        }
        return version;
    }

    public byte[] getEncodedSecret() {
        if (this.encodedSecret == null) {
            return null;
        }
        return (byte[]) this.encodedSecret.clone();
    }
}