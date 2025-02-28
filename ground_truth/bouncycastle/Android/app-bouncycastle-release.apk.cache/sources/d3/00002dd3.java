package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Vector;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;

/* loaded from: classes2.dex */
public interface TlsCrypto {
    TlsSecret adoptSecret(TlsSecret tlsSecret);

    TlsCertificate createCertificate(short s, byte[] bArr) throws IOException;

    TlsCertificate createCertificate(byte[] bArr) throws IOException;

    TlsCipher createCipher(TlsCryptoParameters tlsCryptoParameters, int i, int i2) throws IOException;

    TlsDHDomain createDHDomain(TlsDHConfig tlsDHConfig);

    TlsECDomain createECDomain(TlsECConfig tlsECConfig);

    TlsHMAC createHMAC(int i);

    TlsHMAC createHMACForHash(int i);

    TlsHash createHash(int i);

    TlsKemDomain createKemDomain(TlsKemConfig tlsKemConfig);

    TlsNonceGenerator createNonceGenerator(byte[] bArr);

    TlsSRP6Client createSRP6Client(TlsSRPConfig tlsSRPConfig);

    TlsSRP6Server createSRP6Server(TlsSRPConfig tlsSRPConfig, BigInteger bigInteger);

    TlsSRP6VerifierGenerator createSRP6VerifierGenerator(TlsSRPConfig tlsSRPConfig);

    TlsSecret createSecret(byte[] bArr);

    TlsSecret generateRSAPreMasterSecret(ProtocolVersion protocolVersion);

    SecureRandom getSecureRandom();

    boolean hasAnyStreamVerifiers(Vector vector);

    boolean hasAnyStreamVerifiersLegacy(short[] sArr);

    boolean hasCryptoHashAlgorithm(int i);

    boolean hasCryptoSignatureAlgorithm(int i);

    boolean hasDHAgreement();

    boolean hasECDHAgreement();

    boolean hasEncryptionAlgorithm(int i);

    boolean hasHKDFAlgorithm(int i);

    boolean hasKemAgreement();

    boolean hasMacAlgorithm(int i);

    boolean hasNamedGroup(int i);

    boolean hasRSAEncryption();

    boolean hasSRPAuthentication();

    boolean hasSignatureAlgorithm(short s);

    boolean hasSignatureAndHashAlgorithm(SignatureAndHashAlgorithm signatureAndHashAlgorithm);

    boolean hasSignatureScheme(int i);

    TlsSecret hkdfInit(int i);
}