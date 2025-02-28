package org.openjsse.com.sun.crypto.provider;

import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import org.openjsse.sun.security.internal.spec.TlsMasterSecretParameterSpec;
import sun.security.internal.interfaces.TlsMasterSecret;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/TlsMasterSecretGenerator.class */
public final class TlsMasterSecretGenerator extends KeyGeneratorSpi {
    private static final String MSG = "TlsMasterSecretGenerator must be initialized using a TlsMasterSecretParameterSpec";
    private TlsMasterSecretParameterSpec spec;
    private int protocolVersion;

    @Override // javax.crypto.KeyGeneratorSpi
    protected void engineInit(SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (!(params instanceof TlsMasterSecretParameterSpec)) {
            throw new InvalidAlgorithmParameterException(MSG);
        }
        this.spec = (TlsMasterSecretParameterSpec) params;
        if (!"RAW".equals(this.spec.getPremasterSecret().getFormat())) {
            throw new InvalidAlgorithmParameterException("Key format must be RAW");
        }
        this.protocolVersion = (this.spec.getMajorVersion() << 8) | this.spec.getMinorVersion();
        if (this.protocolVersion < 768 || this.protocolVersion > 771) {
            throw new InvalidAlgorithmParameterException("Only SSL 3.0, TLS 1.0/1.1/1.2 supported");
        }
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected void engineInit(int keysize, SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected SecretKey engineGenerateKey() {
        int premasterMajor;
        int premasterMinor;
        byte[] master;
        byte[] label;
        byte[] seed;
        byte[] doTLS10PRF;
        if (this.spec == null) {
            throw new IllegalStateException("TlsMasterSecretGenerator must be initialized");
        }
        SecretKey premasterKey = this.spec.getPremasterSecret();
        byte[] premaster = premasterKey.getEncoded();
        if (premasterKey.getAlgorithm().equals("TlsRsaPremasterSecret")) {
            premasterMajor = premaster[0] & 255;
            premasterMinor = premaster[1] & 255;
        } else {
            premasterMajor = -1;
            premasterMinor = -1;
        }
        try {
            if (this.protocolVersion >= 769) {
                byte[] extendedMasterSecretSessionHash = this.spec.getExtendedMasterSecretSessionHash();
                if (extendedMasterSecretSessionHash.length != 0) {
                    label = TlsPrfGenerator.LABEL_EXTENDED_MASTER_SECRET;
                    seed = extendedMasterSecretSessionHash;
                } else {
                    byte[] clientRandom = this.spec.getClientRandom();
                    byte[] serverRandom = this.spec.getServerRandom();
                    label = TlsPrfGenerator.LABEL_MASTER_SECRET;
                    seed = TlsPrfGenerator.concat(clientRandom, serverRandom);
                }
                if (this.protocolVersion >= 771) {
                    doTLS10PRF = TlsPrfGenerator.doTLS12PRF(premaster, label, seed, 48, this.spec.getPRFHashAlg(), this.spec.getPRFHashLength(), this.spec.getPRFBlockSize());
                } else {
                    doTLS10PRF = TlsPrfGenerator.doTLS10PRF(premaster, label, seed, 48);
                }
                master = doTLS10PRF;
            } else {
                master = new byte[48];
                MessageDigest md5 = MessageDigest.getInstance("MD5");
                MessageDigest sha = MessageDigest.getInstance("SHA");
                byte[] clientRandom2 = this.spec.getClientRandom();
                byte[] serverRandom2 = this.spec.getServerRandom();
                byte[] tmp = new byte[20];
                for (int i = 0; i < 3; i++) {
                    sha.update(TlsPrfGenerator.SSL3_CONST[i]);
                    sha.update(premaster);
                    sha.update(clientRandom2);
                    sha.update(serverRandom2);
                    sha.digest(tmp, 0, 20);
                    md5.update(premaster);
                    md5.update(tmp);
                    md5.digest(master, i << 4, 16);
                }
            }
            return new TlsMasterSecretKey(master, premasterMajor, premasterMinor);
        } catch (DigestException e) {
            throw new ProviderException(e);
        } catch (NoSuchAlgorithmException e2) {
            throw new ProviderException(e2);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/TlsMasterSecretGenerator$TlsMasterSecretKey.class */
    private static final class TlsMasterSecretKey implements TlsMasterSecret {
        private static final long serialVersionUID = 1019571680375368880L;
        private byte[] key;
        private final int majorVersion;
        private final int minorVersion;

        TlsMasterSecretKey(byte[] key, int majorVersion, int minorVersion) {
            this.key = key;
            this.majorVersion = majorVersion;
            this.minorVersion = minorVersion;
        }

        public int getMajorVersion() {
            return this.majorVersion;
        }

        public int getMinorVersion() {
            return this.minorVersion;
        }

        public String getAlgorithm() {
            return "TlsMasterSecret";
        }

        public String getFormat() {
            return "RAW";
        }

        public byte[] getEncoded() {
            return (byte[]) this.key.clone();
        }
    }
}