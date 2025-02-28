package org.openjsse.com.sun.crypto.provider;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.openjsse.sun.security.internal.spec.TlsKeyMaterialParameterSpec;
import org.openjsse.sun.security.internal.spec.TlsKeyMaterialSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/TlsKeyMaterialGenerator.class */
public final class TlsKeyMaterialGenerator extends KeyGeneratorSpi {
    private static final String MSG = "TlsKeyMaterialGenerator must be initialized using a TlsKeyMaterialParameterSpec";
    private TlsKeyMaterialParameterSpec spec;
    private int protocolVersion;

    @Override // javax.crypto.KeyGeneratorSpi
    protected void engineInit(SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (!(params instanceof TlsKeyMaterialParameterSpec)) {
            throw new InvalidAlgorithmParameterException(MSG);
        }
        this.spec = (TlsKeyMaterialParameterSpec) params;
        if (!"RAW".equals(this.spec.getMasterSecret().getFormat())) {
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
        if (this.spec == null) {
            throw new IllegalStateException("TlsKeyMaterialGenerator must be initialized");
        }
        try {
            return engineGenerateKey0();
        } catch (GeneralSecurityException e) {
            throw new ProviderException(e);
        }
    }

    private SecretKey engineGenerateKey0() throws GeneralSecurityException {
        byte[] keyBlock;
        SecretKey clientCipherKey;
        SecretKey serverCipherKey;
        byte[] masterSecret = this.spec.getMasterSecret().getEncoded();
        byte[] clientRandom = this.spec.getClientRandom();
        byte[] serverRandom = this.spec.getServerRandom();
        SecretKey clientMacKey = null;
        SecretKey serverMacKey = null;
        IvParameterSpec clientIv = null;
        IvParameterSpec serverIv = null;
        int macLength = this.spec.getMacKeyLength();
        int expandedKeyLength = this.spec.getExpandedCipherKeyLength();
        boolean isExportable = expandedKeyLength != 0;
        int keyLength = this.spec.getCipherKeyLength();
        int ivLength = this.spec.getIvLength();
        int keyBlockLen = ((macLength + keyLength) + (isExportable ? 0 : ivLength)) << 1;
        byte[] bArr = new byte[keyBlockLen];
        MessageDigest md5 = null;
        MessageDigest sha = null;
        if (this.protocolVersion >= 771) {
            keyBlock = TlsPrfGenerator.doTLS12PRF(masterSecret, TlsPrfGenerator.LABEL_KEY_EXPANSION, TlsPrfGenerator.concat(serverRandom, clientRandom), keyBlockLen, this.spec.getPRFHashAlg(), this.spec.getPRFHashLength(), this.spec.getPRFBlockSize());
        } else if (this.protocolVersion >= 769) {
            md5 = MessageDigest.getInstance("MD5");
            sha = MessageDigest.getInstance("SHA1");
            keyBlock = TlsPrfGenerator.doTLS10PRF(masterSecret, TlsPrfGenerator.LABEL_KEY_EXPANSION, TlsPrfGenerator.concat(serverRandom, clientRandom), keyBlockLen, md5, sha);
        } else {
            md5 = MessageDigest.getInstance("MD5");
            sha = MessageDigest.getInstance("SHA1");
            keyBlock = new byte[keyBlockLen];
            byte[] tmp = new byte[20];
            int i = 0;
            for (int remaining = keyBlockLen; remaining > 0; remaining -= 16) {
                sha.update(TlsPrfGenerator.SSL3_CONST[i]);
                sha.update(masterSecret);
                sha.update(serverRandom);
                sha.update(clientRandom);
                sha.digest(tmp, 0, 20);
                md5.update(masterSecret);
                md5.update(tmp);
                if (remaining >= 16) {
                    md5.digest(keyBlock, i << 4, 16);
                } else {
                    md5.digest(tmp, 0, 16);
                    System.arraycopy(tmp, 0, keyBlock, i << 4, remaining);
                }
                i++;
            }
        }
        int ofs = 0;
        if (macLength != 0) {
            byte[] tmp2 = new byte[macLength];
            System.arraycopy(keyBlock, 0, tmp2, 0, macLength);
            int ofs2 = 0 + macLength;
            clientMacKey = new SecretKeySpec(tmp2, "Mac");
            System.arraycopy(keyBlock, ofs2, tmp2, 0, macLength);
            ofs = ofs2 + macLength;
            serverMacKey = new SecretKeySpec(tmp2, "Mac");
        }
        if (keyLength == 0) {
            return new TlsKeyMaterialSpec(clientMacKey, serverMacKey);
        }
        String alg = this.spec.getCipherAlgorithm();
        byte[] clientKeyBytes = new byte[keyLength];
        System.arraycopy(keyBlock, ofs, clientKeyBytes, 0, keyLength);
        int ofs3 = ofs + keyLength;
        byte[] serverKeyBytes = new byte[keyLength];
        System.arraycopy(keyBlock, ofs3, serverKeyBytes, 0, keyLength);
        int ofs4 = ofs3 + keyLength;
        if (!isExportable) {
            clientCipherKey = new SecretKeySpec(clientKeyBytes, alg);
            serverCipherKey = new SecretKeySpec(serverKeyBytes, alg);
            if (ivLength != 0) {
                byte[] tmp3 = new byte[ivLength];
                System.arraycopy(keyBlock, ofs4, tmp3, 0, ivLength);
                int ofs5 = ofs4 + ivLength;
                clientIv = new IvParameterSpec(tmp3);
                System.arraycopy(keyBlock, ofs5, tmp3, 0, ivLength);
                int i2 = ofs5 + ivLength;
                serverIv = new IvParameterSpec(tmp3);
            }
        } else if (this.protocolVersion >= 770) {
            throw new RuntimeException("Internal Error:  TLS 1.1+ should not be negotiatingexportable ciphersuites");
        } else {
            if (this.protocolVersion == 769) {
                byte[] seed = TlsPrfGenerator.concat(clientRandom, serverRandom);
                clientCipherKey = new SecretKeySpec(TlsPrfGenerator.doTLS10PRF(clientKeyBytes, TlsPrfGenerator.LABEL_CLIENT_WRITE_KEY, seed, expandedKeyLength, md5, sha), alg);
                serverCipherKey = new SecretKeySpec(TlsPrfGenerator.doTLS10PRF(serverKeyBytes, TlsPrfGenerator.LABEL_SERVER_WRITE_KEY, seed, expandedKeyLength, md5, sha), alg);
                if (ivLength != 0) {
                    byte[] tmp4 = new byte[ivLength];
                    byte[] block = TlsPrfGenerator.doTLS10PRF(null, TlsPrfGenerator.LABEL_IV_BLOCK, seed, ivLength << 1, md5, sha);
                    System.arraycopy(block, 0, tmp4, 0, ivLength);
                    clientIv = new IvParameterSpec(tmp4);
                    System.arraycopy(block, ivLength, tmp4, 0, ivLength);
                    serverIv = new IvParameterSpec(tmp4);
                }
            } else {
                byte[] tmp5 = new byte[expandedKeyLength];
                md5.update(clientKeyBytes);
                md5.update(clientRandom);
                md5.update(serverRandom);
                System.arraycopy(md5.digest(), 0, tmp5, 0, expandedKeyLength);
                clientCipherKey = new SecretKeySpec(tmp5, alg);
                md5.update(serverKeyBytes);
                md5.update(serverRandom);
                md5.update(clientRandom);
                System.arraycopy(md5.digest(), 0, tmp5, 0, expandedKeyLength);
                serverCipherKey = new SecretKeySpec(tmp5, alg);
                if (ivLength != 0) {
                    byte[] tmp6 = new byte[ivLength];
                    md5.update(clientRandom);
                    md5.update(serverRandom);
                    System.arraycopy(md5.digest(), 0, tmp6, 0, ivLength);
                    clientIv = new IvParameterSpec(tmp6);
                    md5.update(serverRandom);
                    md5.update(clientRandom);
                    System.arraycopy(md5.digest(), 0, tmp6, 0, ivLength);
                    serverIv = new IvParameterSpec(tmp6);
                }
            }
        }
        return new TlsKeyMaterialSpec(clientMacKey, serverMacKey, clientCipherKey, clientIv, serverCipherKey, serverIv);
    }
}