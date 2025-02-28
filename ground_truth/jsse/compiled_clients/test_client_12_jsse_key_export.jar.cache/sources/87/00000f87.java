package org.openjsse.sun.security.internal.spec;

import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;

@Deprecated
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/internal/spec/TlsMasterSecretParameterSpec.class */
public class TlsMasterSecretParameterSpec implements AlgorithmParameterSpec {
    private final SecretKey premasterSecret;
    private final int majorVersion;
    private final int minorVersion;
    private final byte[] clientRandom;
    private final byte[] serverRandom;
    private final byte[] extendedMasterSecretSessionHash;
    private final String prfHashAlg;
    private final int prfHashLength;
    private final int prfBlockSize;

    public TlsMasterSecretParameterSpec(SecretKey premasterSecret, int majorVersion, int minorVersion, byte[] clientRandom, byte[] serverRandom, String prfHashAlg, int prfHashLength, int prfBlockSize) {
        this(premasterSecret, majorVersion, minorVersion, clientRandom, serverRandom, new byte[0], prfHashAlg, prfHashLength, prfBlockSize);
    }

    public TlsMasterSecretParameterSpec(SecretKey premasterSecret, int majorVersion, int minorVersion, byte[] extendedMasterSecretSessionHash, String prfHashAlg, int prfHashLength, int prfBlockSize) {
        this(premasterSecret, majorVersion, minorVersion, new byte[0], new byte[0], extendedMasterSecretSessionHash, prfHashAlg, prfHashLength, prfBlockSize);
    }

    private TlsMasterSecretParameterSpec(SecretKey premasterSecret, int majorVersion, int minorVersion, byte[] clientRandom, byte[] serverRandom, byte[] extendedMasterSecretSessionHash, String prfHashAlg, int prfHashLength, int prfBlockSize) {
        if (premasterSecret == null) {
            throw new NullPointerException("premasterSecret must not be null");
        }
        this.premasterSecret = premasterSecret;
        this.majorVersion = checkVersion(majorVersion);
        this.minorVersion = checkVersion(minorVersion);
        this.clientRandom = (byte[]) clientRandom.clone();
        this.serverRandom = (byte[]) serverRandom.clone();
        this.extendedMasterSecretSessionHash = extendedMasterSecretSessionHash != null ? (byte[]) extendedMasterSecretSessionHash.clone() : new byte[0];
        this.prfHashAlg = prfHashAlg;
        this.prfHashLength = prfHashLength;
        this.prfBlockSize = prfBlockSize;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int checkVersion(int version) {
        if (version < 0 || version > 255) {
            throw new IllegalArgumentException("Version must be between 0 and 255");
        }
        return version;
    }

    public SecretKey getPremasterSecret() {
        return this.premasterSecret;
    }

    public int getMajorVersion() {
        return this.majorVersion;
    }

    public int getMinorVersion() {
        return this.minorVersion;
    }

    public byte[] getClientRandom() {
        return (byte[]) this.clientRandom.clone();
    }

    public byte[] getServerRandom() {
        return (byte[]) this.serverRandom.clone();
    }

    public byte[] getExtendedMasterSecretSessionHash() {
        return (byte[]) this.extendedMasterSecretSessionHash.clone();
    }

    public String getPRFHashAlg() {
        return this.prfHashAlg;
    }

    public int getPRFHashLength() {
        return this.prfHashLength;
    }

    public int getPRFBlockSize() {
        return this.prfBlockSize;
    }
}