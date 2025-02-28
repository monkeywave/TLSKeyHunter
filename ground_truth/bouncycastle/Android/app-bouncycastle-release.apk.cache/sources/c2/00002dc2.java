package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Hashtable;
import java.util.Vector;
import kotlin.UByte;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.p009x9.X9ObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.OfferedPsks;
import org.bouncycastle.tls.crypto.Tls13Verifier;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsEncryptor;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.tls.crypto.TlsHashOutputStream;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Shorts;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.p019io.Streams;

/* loaded from: classes2.dex */
public class TlsUtils {
    static final short MINIMUM_HASH_PREFERRED = 4;
    static final short MINIMUM_HASH_STRICT = 2;
    private static byte[] DOWNGRADE_TLS11 = Hex.decodeStrict("444F574E47524400");
    private static byte[] DOWNGRADE_TLS12 = Hex.decodeStrict("444F574E47524401");
    private static final Hashtable CERT_SIG_ALG_OIDS = createCertSigAlgOIDs();
    private static final Vector DEFAULT_SUPPORTED_SIG_ALGS = createDefaultSupportedSigAlgs();
    public static final byte[] EMPTY_BYTES = new byte[0];
    public static final short[] EMPTY_SHORTS = new short[0];
    public static final int[] EMPTY_INTS = new int[0];
    public static final long[] EMPTY_LONGS = new long[0];
    public static final String[] EMPTY_STRINGS = new String[0];

    public static TlsSecret PRF(SecurityParameters securityParameters, TlsSecret tlsSecret, String str, byte[] bArr, int i) {
        return tlsSecret.deriveUsingPRF(securityParameters.getPRFAlgorithm(), str, bArr, i);
    }

    public static TlsSecret PRF(TlsContext tlsContext, TlsSecret tlsSecret, String str, byte[] bArr, int i) {
        return PRF(tlsContext.getSecurityParametersHandshake(), tlsSecret, str, bArr, i);
    }

    private static void addCertSigAlgOID(Hashtable hashtable, ASN1ObjectIdentifier aSN1ObjectIdentifier, SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        hashtable.put(aSN1ObjectIdentifier.getId(), signatureAndHashAlgorithm);
    }

    private static void addCertSigAlgOID(Hashtable hashtable, ASN1ObjectIdentifier aSN1ObjectIdentifier, short s, short s2) {
        addCertSigAlgOID(hashtable, aSN1ObjectIdentifier, SignatureAndHashAlgorithm.getInstance(s, s2));
    }

    public static void addIfSupported(Vector vector, TlsCrypto tlsCrypto, int i) {
        if (tlsCrypto.hasNamedGroup(i)) {
            vector.addElement(Integers.valueOf(i));
        }
    }

    public static void addIfSupported(Vector vector, TlsCrypto tlsCrypto, SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        if (tlsCrypto.hasSignatureAndHashAlgorithm(signatureAndHashAlgorithm)) {
            vector.addElement(signatureAndHashAlgorithm);
        }
    }

    public static void addIfSupported(Vector vector, TlsCrypto tlsCrypto, int[] iArr) {
        for (int i : iArr) {
            addIfSupported(vector, tlsCrypto, i);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Hashtable addKeyShareToClientHello(TlsClientContext tlsClientContext, TlsClient tlsClient, Hashtable hashtable) throws IOException {
        if (isTLSv13(tlsClientContext.getClientVersion()) && hashtable.containsKey(TlsExtensionsUtils.EXT_supported_groups)) {
            int[] supportedGroupsExtension = TlsExtensionsUtils.getSupportedGroupsExtension(hashtable);
            Vector earlyKeyShareGroups = tlsClient.getEarlyKeyShareGroups();
            Hashtable hashtable2 = new Hashtable(3);
            Vector vector = new Vector(2);
            collectKeyShares(tlsClientContext, supportedGroupsExtension, earlyKeyShareGroups, hashtable2, vector);
            TlsExtensionsUtils.addKeyShareClientHello(hashtable, vector);
            return hashtable2;
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Hashtable addKeyShareToClientHelloRetry(TlsClientContext tlsClientContext, Hashtable hashtable, int i) throws IOException {
        int[] iArr = {i};
        Vector vectorOfOne = vectorOfOne(Integers.valueOf(i));
        Hashtable hashtable2 = new Hashtable(1, 1.0f);
        Vector vector = new Vector(1);
        collectKeyShares(tlsClientContext, iArr, vectorOfOne, hashtable2, vector);
        TlsExtensionsUtils.addKeyShareClientHello(hashtable, vector);
        if (hashtable2.isEmpty() || vector.isEmpty()) {
            throw new TlsFatalAlert((short) 80);
        }
        return hashtable2;
    }

    static void addPreSharedKeyToClientExtensions(TlsPSK[] tlsPSKArr, Hashtable hashtable) throws IOException {
        Vector vector = new Vector(tlsPSKArr.length);
        for (TlsPSK tlsPSK : tlsPSKArr) {
            vector.add(new PskIdentity(tlsPSK.getIdentity(), 0L));
        }
        TlsExtensionsUtils.addPreSharedKeyClientHello(hashtable, new OfferedPsks(vector));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static OfferedPsks.BindersConfig addPreSharedKeyToClientHello(TlsClientContext tlsClientContext, TlsClient tlsClient, Hashtable hashtable, int[] iArr) throws IOException {
        TlsPSKExternal[] pSKExternalsClient;
        if (isTLSv13(tlsClientContext.getClientVersion()) && (pSKExternalsClient = getPSKExternalsClient(tlsClient, iArr)) != null) {
            short[] pskKeyExchangeModes = tlsClient.getPskKeyExchangeModes();
            if (isNullOrEmpty(pskKeyExchangeModes)) {
                throw new TlsFatalAlert((short) 80, "External PSKs configured but no PskKeyExchangeMode available");
            }
            TlsSecret[] pSKEarlySecrets = getPSKEarlySecrets(tlsClientContext.getCrypto(), pSKExternalsClient);
            int bindersSize = OfferedPsks.getBindersSize(pSKExternalsClient);
            addPreSharedKeyToClientExtensions(pSKExternalsClient, hashtable);
            TlsExtensionsUtils.addPSKKeyExchangeModesExtension(hashtable, pskKeyExchangeModes);
            return new OfferedPsks.BindersConfig(pSKExternalsClient, pskKeyExchangeModes, pSKEarlySecrets, bindersSize);
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static OfferedPsks.BindersConfig addPreSharedKeyToClientHelloRetry(TlsClientContext tlsClientContext, OfferedPsks.BindersConfig bindersConfig, Hashtable hashtable) throws IOException {
        Vector pSKIndices = getPSKIndices(bindersConfig.psks, getPRFAlgorithm13(tlsClientContext.getSecurityParametersHandshake().getCipherSuite()));
        if (pSKIndices.isEmpty()) {
            return null;
        }
        int size = pSKIndices.size();
        if (size < bindersConfig.psks.length) {
            TlsPSK[] tlsPSKArr = new TlsPSK[size];
            TlsSecret[] tlsSecretArr = new TlsSecret[size];
            for (int i = 0; i < size; i++) {
                int intValue = ((Integer) pSKIndices.elementAt(i)).intValue();
                tlsPSKArr[i] = bindersConfig.psks[intValue];
                tlsSecretArr[i] = bindersConfig.earlySecrets[intValue];
            }
            bindersConfig = new OfferedPsks.BindersConfig(tlsPSKArr, bindersConfig.pskKeyExchangeModes, tlsSecretArr, OfferedPsks.getBindersSize(tlsPSKArr));
        }
        addPreSharedKeyToClientExtensions(bindersConfig.psks, hashtable);
        return bindersConfig;
    }

    public static boolean addToSet(Vector vector, int i) {
        boolean contains = vector.contains(Integers.valueOf(i));
        boolean z = !contains;
        if (!contains) {
            vector.add(Integers.valueOf(i));
        }
        return z;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void adjustTranscriptForRetry(TlsHandshakeHash tlsHandshakeHash) throws IOException {
        byte[] currentPRFHash = getCurrentPRFHash(tlsHandshakeHash);
        tlsHandshakeHash.reset();
        int length = currentPRFHash.length;
        checkUint8(length);
        int i = length + 4;
        byte[] bArr = new byte[i];
        writeUint8((short) HandshakeType.message_hash, bArr, 0);
        writeUint24(length, bArr, 1);
        System.arraycopy(currentPRFHash, 0, bArr, 4, length);
        tlsHandshakeHash.update(bArr, 0, i);
    }

    private static boolean areCertificatesEqual(Certificate certificate, Certificate certificate2) {
        int length = certificate.getLength();
        if (certificate2.getLength() == length) {
            for (int i = 0; i < length; i++) {
                try {
                    if (!Arrays.areEqual(certificate.getCertificateAt(i).getEncoded(), certificate2.getCertificateAt(i).getEncoded())) {
                        return false;
                    }
                } catch (IOException unused) {
                }
            }
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] calculateEndPointHash(TlsContext tlsContext, TlsCertificate tlsCertificate, byte[] bArr) throws IOException {
        return calculateEndPointHash(tlsContext, tlsCertificate, bArr, 0, bArr.length);
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0060  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    static byte[] calculateEndPointHash(org.bouncycastle.tls.TlsContext r4, org.bouncycastle.tls.crypto.TlsCertificate r5, byte[] r6, int r7, int r8) throws java.io.IOException {
        /*
            java.lang.String r0 = r5.getSigAlgOID()
            r1 = 4
            r2 = 0
            if (r0 == 0) goto L53
            org.bouncycastle.asn1.ASN1ObjectIdentifier r3 = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_RSASSA_PSS
            java.lang.String r3 = r3.getId()
            boolean r3 = r3.equals(r0)
            if (r3 == 0) goto L44
            org.bouncycastle.asn1.ASN1Encodable r5 = r5.getSigAlgParams()
            org.bouncycastle.asn1.pkcs.RSASSAPSSparams r5 = org.bouncycastle.asn1.pkcs.RSASSAPSSparams.getInstance(r5)
            if (r5 == 0) goto L53
            org.bouncycastle.asn1.x509.AlgorithmIdentifier r5 = r5.getHashAlgorithm()
            org.bouncycastle.asn1.ASN1ObjectIdentifier r5 = r5.getAlgorithm()
            org.bouncycastle.asn1.ASN1ObjectIdentifier r0 = org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256
            boolean r0 = r0.equals(r5)
            if (r0 == 0) goto L30
            r5 = r1
            goto L54
        L30:
            org.bouncycastle.asn1.ASN1ObjectIdentifier r0 = org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha384
            boolean r0 = r0.equals(r5)
            if (r0 == 0) goto L3a
            r5 = 5
            goto L54
        L3a:
            org.bouncycastle.asn1.ASN1ObjectIdentifier r0 = org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha512
            boolean r5 = r0.equals(r5)
            if (r5 == 0) goto L53
            r5 = 6
            goto L54
        L44:
            java.util.Hashtable r5 = org.bouncycastle.tls.TlsUtils.CERT_SIG_ALG_OIDS
            java.lang.Object r5 = r5.get(r0)
            org.bouncycastle.tls.SignatureAndHashAlgorithm r5 = (org.bouncycastle.tls.SignatureAndHashAlgorithm) r5
            if (r5 == 0) goto L53
            short r5 = r5.getHash()
            goto L54
        L53:
            r5 = r2
        L54:
            r0 = 1
            if (r5 == r0) goto L61
            r0 = 2
            if (r5 == r0) goto L61
            r0 = 8
            if (r5 == r0) goto L60
            r1 = r5
            goto L61
        L60:
            r1 = r2
        L61:
            if (r1 == 0) goto L75
            org.bouncycastle.tls.crypto.TlsCrypto r4 = r4.getCrypto()
            org.bouncycastle.tls.crypto.TlsHash r4 = createHash(r4, r1)
            if (r4 == 0) goto L75
            r4.update(r6, r7, r8)
            byte[] r4 = r4.calculateHash()
            return r4
        L75:
            byte[] r4 = org.bouncycastle.tls.TlsUtils.EMPTY_BYTES
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.TlsUtils.calculateEndPointHash(org.bouncycastle.tls.TlsContext, org.bouncycastle.tls.crypto.TlsCertificate, byte[], int, int):byte[]");
    }

    public static byte[] calculateExporterSeed(SecurityParameters securityParameters, byte[] bArr) {
        byte[] clientRandom = securityParameters.getClientRandom();
        byte[] serverRandom = securityParameters.getServerRandom();
        if (bArr == null) {
            return Arrays.concatenate(clientRandom, serverRandom);
        }
        if (isValidUint16(bArr.length)) {
            byte[] bArr2 = new byte[2];
            writeUint16(bArr.length, bArr2, 0);
            return Arrays.concatenate(clientRandom, serverRandom, bArr2, bArr);
        }
        throw new IllegalArgumentException("'context' must have length less than 2^16 (or be null)");
    }

    private static byte[] calculateFinishedHMAC(int i, int i2, TlsSecret tlsSecret, byte[] bArr) throws IOException {
        TlsSecret hkdfExpandLabel = TlsCryptoUtils.hkdfExpandLabel(tlsSecret, i, "finished", EMPTY_BYTES, i2);
        try {
            return hkdfExpandLabel.calculateHMAC(i, bArr, 0, bArr.length);
        } finally {
            hkdfExpandLabel.destroy();
        }
    }

    private static byte[] calculateFinishedHMAC(SecurityParameters securityParameters, TlsSecret tlsSecret, byte[] bArr) throws IOException {
        return calculateFinishedHMAC(securityParameters.getPRFCryptoHashAlgorithm(), securityParameters.getPRFHashLength(), tlsSecret, bArr);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TlsSecret calculateMasterSecret(TlsContext tlsContext, TlsSecret tlsSecret) {
        byte[] concat;
        String str;
        SecurityParameters securityParametersHandshake = tlsContext.getSecurityParametersHandshake();
        if (securityParametersHandshake.isExtendedMasterSecret()) {
            concat = securityParametersHandshake.getSessionHash();
            str = ExporterLabel.extended_master_secret;
        } else {
            concat = concat(securityParametersHandshake.getClientRandom(), securityParametersHandshake.getServerRandom());
            str = "master secret";
        }
        return PRF(securityParametersHandshake, tlsSecret, str, concat, 48);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] calculatePSKBinder(TlsCrypto tlsCrypto, boolean z, int i, TlsSecret tlsSecret, byte[] bArr) throws IOException {
        int hashOutputSize = TlsCryptoUtils.getHashOutputSize(i);
        TlsSecret deriveSecret = deriveSecret(i, hashOutputSize, tlsSecret, z ? "ext binder" : "res binder", tlsCrypto.createHash(i).calculateHash());
        try {
            return calculateFinishedHMAC(i, hashOutputSize, deriveSecret, bArr);
        } finally {
            deriveSecret.destroy();
        }
    }

    static byte[] calculateSignatureHash(TlsContext tlsContext, SignatureAndHashAlgorithm signatureAndHashAlgorithm, byte[] bArr, DigestInputBuffer digestInputBuffer) {
        TlsCrypto crypto = tlsContext.getCrypto();
        TlsHash combinedHash = signatureAndHashAlgorithm == null ? new CombinedHash(crypto) : createHash(crypto, signatureAndHashAlgorithm);
        SecurityParameters securityParametersHandshake = tlsContext.getSecurityParametersHandshake();
        byte[] concatenate = Arrays.concatenate(securityParametersHandshake.getClientRandom(), securityParametersHandshake.getServerRandom());
        combinedHash.update(concatenate, 0, concatenate.length);
        if (bArr != null) {
            combinedHash.update(bArr, 0, bArr.length);
        }
        digestInputBuffer.updateDigest(combinedHash);
        return combinedHash.calculateHash();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] calculateVerifyData(TlsContext tlsContext, TlsHandshakeHash tlsHandshakeHash, boolean z) throws IOException {
        SecurityParameters securityParametersHandshake = tlsContext.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParametersHandshake.getNegotiatedVersion();
        if (isTLSv13(negotiatedVersion)) {
            return calculateFinishedHMAC(securityParametersHandshake, z ? securityParametersHandshake.getBaseKeyServer() : securityParametersHandshake.getBaseKeyClient(), getCurrentPRFHash(tlsHandshakeHash));
        } else if (negotiatedVersion.isSSL()) {
            return SSL3Utils.calculateVerifyData(tlsHandshakeHash, z);
        } else {
            return PRF(securityParametersHandshake, securityParametersHandshake.getMasterSecret(), z ? ExporterLabel.server_finished : ExporterLabel.client_finished, getCurrentPRFHash(tlsHandshakeHash), securityParametersHandshake.getVerifyDataLength()).extract();
        }
    }

    private static void checkClientCertificateType(CertificateRequest certificateRequest, short s, short s2) throws IOException {
        if (s < 0 || !Arrays.contains(certificateRequest.getCertificateTypes(), s)) {
            throw new TlsFatalAlert(s2);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void checkDowngradeMarker(ProtocolVersion protocolVersion, byte[] bArr) throws IOException {
        ProtocolVersion equivalentTLSVersion = protocolVersion.getEquivalentTLSVersion();
        if (equivalentTLSVersion.isEqualOrEarlierVersionOf(ProtocolVersion.TLSv11)) {
            checkDowngradeMarker(bArr, DOWNGRADE_TLS11);
        }
        if (equivalentTLSVersion.isEqualOrEarlierVersionOf(ProtocolVersion.TLSv12)) {
            checkDowngradeMarker(bArr, DOWNGRADE_TLS12);
        }
    }

    private static void checkDowngradeMarker(byte[] bArr, byte[] bArr2) throws IOException {
        int length = bArr2.length;
        if (constantTimeAreEqual(length, bArr2, 0, bArr, bArr.length - length)) {
            throw new TlsFatalAlert((short) 47);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Removed duplicated region for block: B:5:0x000a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static void checkExtensionData13(java.util.Hashtable r2, int r3, short r4) throws java.io.IOException {
        /*
            java.util.Enumeration r2 = r2.keys()
        L4:
            boolean r0 = r2.hasMoreElements()
            if (r0 == 0) goto L3a
            java.lang.Object r0 = r2.nextElement()
            java.lang.Integer r0 = (java.lang.Integer) r0
            if (r0 == 0) goto L1d
            int r1 = r0.intValue()
            boolean r1 = isPermittedExtensionType13(r3, r1)
            if (r1 == 0) goto L1d
            goto L4
        L1d:
            org.bouncycastle.tls.TlsFatalAlert r2 = new org.bouncycastle.tls.TlsFatalAlert
            java.lang.StringBuilder r3 = new java.lang.StringBuilder
            java.lang.String r1 = "Invalid extension: "
            r3.<init>(r1)
            int r0 = r0.intValue()
            java.lang.String r0 = org.bouncycastle.tls.ExtensionType.getText(r0)
            java.lang.StringBuilder r3 = r3.append(r0)
            java.lang.String r3 = r3.toString()
            r2.<init>(r4, r3)
            throw r2
        L3a:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.TlsUtils.checkExtensionData13(java.util.Hashtable, int, short):void");
    }

    public static void checkPeerSigAlgs(TlsContext tlsContext, TlsCertificate[] tlsCertificateArr) throws IOException {
        if (tlsContext.isServer()) {
            checkSigAlgOfClientCerts(tlsContext, tlsCertificateArr);
        } else {
            checkSigAlgOfServerCerts(tlsContext, tlsCertificateArr);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x0042 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private static void checkSigAlgOfClientCerts(org.bouncycastle.tls.TlsContext r9, org.bouncycastle.tls.crypto.TlsCertificate[] r10) throws java.io.IOException {
        /*
            org.bouncycastle.tls.SecurityParameters r9 = r9.getSecurityParametersHandshake()
            short[] r0 = r9.getClientCertTypes()
            java.util.Vector r9 = r9.getServerSigAlgsCert()
            int r1 = r10.length
            r2 = 1
            int r1 = r1 - r2
            r3 = 0
            r4 = r3
        L11:
            if (r4 >= r1) goto L4a
            r5 = r10[r4]
            int r4 = r4 + 1
            r6 = r10[r4]
            org.bouncycastle.tls.SignatureAndHashAlgorithm r5 = getCertSigAndHashAlg(r5, r6)
            if (r5 != 0) goto L20
            goto L39
        L20:
            if (r9 != 0) goto L3b
            if (r0 == 0) goto L39
            r6 = r3
        L25:
            int r7 = r0.length
            if (r6 >= r7) goto L39
            short r7 = r0[r6]
            short r7 = getLegacySignatureAlgorithmClientCert(r7)
            short r8 = r5.getSignature()
            if (r8 != r7) goto L36
            r5 = r2
            goto L3f
        L36:
            int r6 = r6 + 1
            goto L25
        L39:
            r5 = r3
            goto L3f
        L3b:
            boolean r5 = containsSignatureAlgorithm(r9, r5)
        L3f:
            if (r5 == 0) goto L42
            goto L11
        L42:
            org.bouncycastle.tls.TlsFatalAlert r9 = new org.bouncycastle.tls.TlsFatalAlert
            r10 = 42
            r9.<init>(r10)
            throw r9
        L4a:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.TlsUtils.checkSigAlgOfClientCerts(org.bouncycastle.tls.TlsContext, org.bouncycastle.tls.crypto.TlsCertificate[]):void");
    }

    private static void checkSigAlgOfServerCerts(TlsContext tlsContext, TlsCertificate[] tlsCertificateArr) throws IOException {
        SecurityParameters securityParametersHandshake = tlsContext.getSecurityParametersHandshake();
        Vector clientSigAlgsCert = securityParametersHandshake.getClientSigAlgsCert();
        Vector vector = (securityParametersHandshake.getClientSigAlgs() == clientSigAlgsCert || isTLSv13(securityParametersHandshake.getNegotiatedVersion())) ? null : null;
        int length = tlsCertificateArr.length - 1;
        int i = 0;
        while (i < length) {
            TlsCertificate tlsCertificate = tlsCertificateArr[i];
            i++;
            SignatureAndHashAlgorithm certSigAndHashAlg = getCertSigAndHashAlg(tlsCertificate, tlsCertificateArr[i]);
            if (certSigAndHashAlg != null) {
                if (clientSigAlgsCert == null) {
                    if (getLegacySignatureAlgorithmServerCert(securityParametersHandshake.getKeyExchangeAlgorithm()) == certSigAndHashAlg.getSignature()) {
                    }
                } else if (containsSignatureAlgorithm(clientSigAlgsCert, certSigAndHashAlg)) {
                    continue;
                } else if (vector != null && containsSignatureAlgorithm(vector, certSigAndHashAlg)) {
                }
            }
            throw new TlsFatalAlert((short) 42);
        }
    }

    static void checkTlsFeatures(Certificate certificate, Hashtable hashtable, Hashtable hashtable2) throws IOException {
        byte[] extension = certificate.getCertificateAt(0).getExtension(TlsObjectIdentifiers.id_pe_tlsfeature);
        if (extension != null) {
            ASN1Sequence aSN1Sequence = (ASN1Sequence) readASN1Object(extension);
            for (int i = 0; i < aSN1Sequence.size(); i++) {
                if (!(aSN1Sequence.getObjectAt(i) instanceof ASN1Integer)) {
                    throw new TlsFatalAlert((short) 42);
                }
            }
            requireDEREncoding(aSN1Sequence, extension);
            for (int i2 = 0; i2 < aSN1Sequence.size(); i2++) {
                BigInteger positiveValue = ((ASN1Integer) aSN1Sequence.getObjectAt(i2)).getPositiveValue();
                if (positiveValue.bitLength() <= 16) {
                    Integer valueOf = Integers.valueOf(positiveValue.intValue());
                    if (hashtable.containsKey(valueOf) && !hashtable2.containsKey(valueOf)) {
                        throw new TlsFatalAlert((short) 46);
                    }
                }
            }
        }
    }

    public static void checkUint16(int i) throws IOException {
        if (!isValidUint16(i)) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    public static void checkUint16(long j) throws IOException {
        if (!isValidUint16(j)) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    public static void checkUint24(int i) throws IOException {
        if (!isValidUint24(i)) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    public static void checkUint24(long j) throws IOException {
        if (!isValidUint24(j)) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    public static void checkUint32(long j) throws IOException {
        if (!isValidUint32(j)) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    public static void checkUint48(long j) throws IOException {
        if (!isValidUint48(j)) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    public static void checkUint64(long j) throws IOException {
        if (!isValidUint64(j)) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    public static void checkUint8(int i) throws IOException {
        if (!isValidUint8(i)) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    public static void checkUint8(long j) throws IOException {
        if (!isValidUint8(j)) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    public static void checkUint8(short s) throws IOException {
        if (!isValidUint8(s)) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    public static SignatureAndHashAlgorithm chooseSignatureAndHashAlgorithm(ProtocolVersion protocolVersion, Vector vector, short s) throws IOException {
        short hash;
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
        if (isTLSv12(protocolVersion)) {
            if (vector == null) {
                vector = getDefaultSignatureAlgorithms(s);
            }
            for (int i = 0; i < vector.size(); i++) {
                SignatureAndHashAlgorithm signatureAndHashAlgorithm2 = (SignatureAndHashAlgorithm) vector.elementAt(i);
                if (signatureAndHashAlgorithm2.getSignature() == s && (hash = signatureAndHashAlgorithm2.getHash()) >= 2) {
                    if (signatureAndHashAlgorithm != null) {
                        short hash2 = signatureAndHashAlgorithm.getHash();
                        if (hash2 < 4) {
                            if (hash <= hash2) {
                            }
                        } else if (hash >= 4) {
                            if (hash >= hash2) {
                            }
                        }
                    }
                    signatureAndHashAlgorithm = signatureAndHashAlgorithm2;
                }
            }
            if (signatureAndHashAlgorithm != null) {
                return signatureAndHashAlgorithm;
            }
            throw new TlsFatalAlert((short) 80);
        }
        return null;
    }

    public static SignatureAndHashAlgorithm chooseSignatureAndHashAlgorithm(TlsContext tlsContext, Vector vector, short s) throws IOException {
        return chooseSignatureAndHashAlgorithm(tlsContext.getServerVersion(), vector, s);
    }

    public static byte[] clone(byte[] bArr) {
        if (bArr == null) {
            return null;
        }
        return bArr.length == 0 ? EMPTY_BYTES : (byte[]) bArr.clone();
    }

    public static String[] clone(String[] strArr) {
        if (strArr == null) {
            return null;
        }
        return strArr.length < 1 ? EMPTY_STRINGS : (String[]) strArr.clone();
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x0085  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0094 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private static void collectKeyShares(org.bouncycastle.tls.TlsClientContext r7, int[] r8, java.util.Vector r9, java.util.Hashtable r10, java.util.Vector r11) throws java.io.IOException {
        /*
            org.bouncycastle.tls.crypto.TlsCrypto r7 = r7.getCrypto()
            boolean r0 = isNullOrEmpty(r8)
            if (r0 == 0) goto Lb
            return
        Lb:
            if (r9 == 0) goto L97
            boolean r0 = r9.isEmpty()
            if (r0 == 0) goto L15
            goto L97
        L15:
            r0 = 0
            r1 = r0
        L17:
            int r2 = r8.length
            if (r1 >= r2) goto L97
            r2 = r8[r1]
            java.lang.Integer r3 = org.bouncycastle.util.Integers.valueOf(r2)
            boolean r4 = r9.contains(r3)
            if (r4 == 0) goto L94
            boolean r4 = r10.containsKey(r3)
            if (r4 != 0) goto L94
            boolean r4 = r7.hasNamedGroup(r2)
            if (r4 != 0) goto L33
            goto L94
        L33:
            boolean r4 = org.bouncycastle.tls.NamedGroup.refersToAnECDHCurve(r2)
            if (r4 == 0) goto L4d
            boolean r4 = r7.hasECDHAgreement()
            if (r4 == 0) goto L82
            org.bouncycastle.tls.crypto.TlsECConfig r4 = new org.bouncycastle.tls.crypto.TlsECConfig
            r4.<init>(r2)
            org.bouncycastle.tls.crypto.TlsECDomain r4 = r7.createECDomain(r4)
            org.bouncycastle.tls.crypto.TlsAgreement r4 = r4.createECDH()
            goto L83
        L4d:
            boolean r4 = org.bouncycastle.tls.NamedGroup.refersToASpecificFiniteField(r2)
            if (r4 == 0) goto L68
            boolean r4 = r7.hasDHAgreement()
            if (r4 == 0) goto L82
            org.bouncycastle.tls.crypto.TlsDHConfig r4 = new org.bouncycastle.tls.crypto.TlsDHConfig
            r5 = 1
            r4.<init>(r2, r5)
            org.bouncycastle.tls.crypto.TlsDHDomain r4 = r7.createDHDomain(r4)
            org.bouncycastle.tls.crypto.TlsAgreement r4 = r4.createDH()
            goto L83
        L68:
            boolean r4 = org.bouncycastle.tls.NamedGroup.refersToASpecificKem(r2)
            if (r4 == 0) goto L82
            boolean r4 = r7.hasKemAgreement()
            if (r4 == 0) goto L82
            org.bouncycastle.tls.crypto.TlsKemConfig r4 = new org.bouncycastle.tls.crypto.TlsKemConfig
            r4.<init>(r2, r0)
            org.bouncycastle.tls.crypto.TlsKemDomain r4 = r7.createKemDomain(r4)
            org.bouncycastle.tls.crypto.TlsAgreement r4 = r4.createKem()
            goto L83
        L82:
            r4 = 0
        L83:
            if (r4 == 0) goto L94
            byte[] r5 = r4.generateEphemeral()
            org.bouncycastle.tls.KeyShareEntry r6 = new org.bouncycastle.tls.KeyShareEntry
            r6.<init>(r2, r5)
            r11.addElement(r6)
            r10.put(r3, r4)
        L94:
            int r1 = r1 + 1
            goto L17
        L97:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.TlsUtils.collectKeyShares(org.bouncycastle.tls.TlsClientContext, int[], java.util.Vector, java.util.Hashtable, java.util.Vector):void");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] concat(byte[] bArr, byte[] bArr2) {
        byte[] bArr3 = new byte[bArr.length + bArr2.length];
        System.arraycopy(bArr, 0, bArr3, 0, bArr.length);
        System.arraycopy(bArr2, 0, bArr3, bArr.length, bArr2.length);
        return bArr3;
    }

    public static boolean constantTimeAreEqual(int i, byte[] bArr, int i2, byte[] bArr2, int i3) {
        int i4 = 0;
        for (int i5 = 0; i5 < i; i5++) {
            i4 |= bArr[i2 + i5] ^ bArr2[i3 + i5];
        }
        return i4 == 0;
    }

    static boolean contains(int[] iArr, int i, int i2, int i3) {
        for (int i4 = 0; i4 < i2; i4++) {
            if (i3 == iArr[i + i4]) {
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean contains(short[] sArr, int i, int i2, short s) {
        for (int i3 = 0; i3 < i2; i3++) {
            if (s == sArr[i + i3]) {
                return true;
            }
        }
        return false;
    }

    static boolean containsAll(short[] sArr, short[] sArr2) {
        for (short s : sArr2) {
            if (!Arrays.contains(sArr, s)) {
                return false;
            }
        }
        return true;
    }

    public static boolean containsAnySignatureAlgorithm(Vector vector, short s) {
        for (int i = 0; i < vector.size(); i++) {
            if (((SignatureAndHashAlgorithm) vector.elementAt(i)).getSignature() == s) {
                return true;
            }
        }
        return false;
    }

    public static boolean containsNonAscii(String str) {
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) >= 128) {
                return true;
            }
        }
        return false;
    }

    public static boolean containsNonAscii(byte[] bArr) {
        for (byte b : bArr) {
            if ((b & UByte.MAX_VALUE) >= 128) {
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean containsNot(short[] sArr, int i, int i2, short s) {
        for (int i3 = 0; i3 < i2; i3++) {
            if (s != sArr[i + i3]) {
                return true;
            }
        }
        return false;
    }

    public static boolean containsSignatureAlgorithm(Vector vector, SignatureAndHashAlgorithm signatureAndHashAlgorithm) throws IOException {
        for (int i = 0; i < vector.size(); i++) {
            if (((SignatureAndHashAlgorithm) vector.elementAt(i)).equals(signatureAndHashAlgorithm)) {
                return true;
            }
        }
        return false;
    }

    public static byte[] copyOfRangeExact(byte[] bArr, int i, int i2) {
        int i3 = i2 - i;
        byte[] bArr2 = new byte[i3];
        System.arraycopy(bArr, i, bArr2, 0, i3);
        return bArr2;
    }

    private static Hashtable createCertSigAlgOIDs() {
        Hashtable hashtable = new Hashtable();
        addCertSigAlgOID(hashtable, NISTObjectIdentifiers.dsa_with_sha224, (short) 3, (short) 2);
        addCertSigAlgOID(hashtable, NISTObjectIdentifiers.dsa_with_sha256, (short) 4, (short) 2);
        addCertSigAlgOID(hashtable, NISTObjectIdentifiers.dsa_with_sha384, (short) 5, (short) 2);
        addCertSigAlgOID(hashtable, NISTObjectIdentifiers.dsa_with_sha512, (short) 6, (short) 2);
        addCertSigAlgOID(hashtable, OIWObjectIdentifiers.dsaWithSHA1, (short) 2, (short) 2);
        addCertSigAlgOID(hashtable, OIWObjectIdentifiers.sha1WithRSA, (short) 2, (short) 1);
        addCertSigAlgOID(hashtable, PKCSObjectIdentifiers.sha1WithRSAEncryption, (short) 2, (short) 1);
        addCertSigAlgOID(hashtable, PKCSObjectIdentifiers.sha224WithRSAEncryption, (short) 3, (short) 1);
        addCertSigAlgOID(hashtable, PKCSObjectIdentifiers.sha256WithRSAEncryption, (short) 4, (short) 1);
        addCertSigAlgOID(hashtable, PKCSObjectIdentifiers.sha384WithRSAEncryption, (short) 5, (short) 1);
        addCertSigAlgOID(hashtable, PKCSObjectIdentifiers.sha512WithRSAEncryption, (short) 6, (short) 1);
        addCertSigAlgOID(hashtable, X9ObjectIdentifiers.ecdsa_with_SHA1, (short) 2, (short) 3);
        addCertSigAlgOID(hashtable, X9ObjectIdentifiers.ecdsa_with_SHA224, (short) 3, (short) 3);
        addCertSigAlgOID(hashtable, X9ObjectIdentifiers.ecdsa_with_SHA256, (short) 4, (short) 3);
        addCertSigAlgOID(hashtable, X9ObjectIdentifiers.ecdsa_with_SHA384, (short) 5, (short) 3);
        addCertSigAlgOID(hashtable, X9ObjectIdentifiers.ecdsa_with_SHA512, (short) 6, (short) 3);
        addCertSigAlgOID(hashtable, X9ObjectIdentifiers.id_dsa_with_sha1, (short) 2, (short) 2);
        addCertSigAlgOID(hashtable, EACObjectIdentifiers.id_TA_ECDSA_SHA_1, (short) 2, (short) 3);
        addCertSigAlgOID(hashtable, EACObjectIdentifiers.id_TA_ECDSA_SHA_224, (short) 3, (short) 3);
        addCertSigAlgOID(hashtable, EACObjectIdentifiers.id_TA_ECDSA_SHA_256, (short) 4, (short) 3);
        addCertSigAlgOID(hashtable, EACObjectIdentifiers.id_TA_ECDSA_SHA_384, (short) 5, (short) 3);
        addCertSigAlgOID(hashtable, EACObjectIdentifiers.id_TA_ECDSA_SHA_512, (short) 6, (short) 3);
        addCertSigAlgOID(hashtable, EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_1, (short) 2, (short) 1);
        addCertSigAlgOID(hashtable, EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_256, (short) 4, (short) 1);
        addCertSigAlgOID(hashtable, BSIObjectIdentifiers.ecdsa_plain_SHA1, (short) 2, (short) 3);
        addCertSigAlgOID(hashtable, BSIObjectIdentifiers.ecdsa_plain_SHA224, (short) 3, (short) 3);
        addCertSigAlgOID(hashtable, BSIObjectIdentifiers.ecdsa_plain_SHA256, (short) 4, (short) 3);
        addCertSigAlgOID(hashtable, BSIObjectIdentifiers.ecdsa_plain_SHA384, (short) 5, (short) 3);
        addCertSigAlgOID(hashtable, BSIObjectIdentifiers.ecdsa_plain_SHA512, (short) 6, (short) 3);
        addCertSigAlgOID(hashtable, EdECObjectIdentifiers.id_Ed25519, SignatureAndHashAlgorithm.ed25519);
        addCertSigAlgOID(hashtable, EdECObjectIdentifiers.id_Ed448, SignatureAndHashAlgorithm.ed448);
        addCertSigAlgOID(hashtable, RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, SignatureAndHashAlgorithm.gostr34102012_256);
        addCertSigAlgOID(hashtable, RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, SignatureAndHashAlgorithm.gostr34102012_512);
        return hashtable;
    }

    private static Vector createDefaultSupportedSigAlgs() {
        Vector vector = new Vector();
        vector.addElement(SignatureAndHashAlgorithm.ed25519);
        vector.addElement(SignatureAndHashAlgorithm.ed448);
        vector.addElement(SignatureAndHashAlgorithm.getInstance((short) 4, (short) 3));
        vector.addElement(SignatureAndHashAlgorithm.getInstance((short) 5, (short) 3));
        vector.addElement(SignatureAndHashAlgorithm.getInstance((short) 6, (short) 3));
        vector.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
        vector.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha384);
        vector.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha512);
        vector.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha256);
        vector.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha384);
        vector.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha512);
        vector.addElement(SignatureAndHashAlgorithm.getInstance((short) 4, (short) 1));
        vector.addElement(SignatureAndHashAlgorithm.getInstance((short) 5, (short) 1));
        vector.addElement(SignatureAndHashAlgorithm.getInstance((short) 6, (short) 1));
        vector.addElement(SignatureAndHashAlgorithm.getInstance((short) 4, (short) 2));
        vector.addElement(SignatureAndHashAlgorithm.getInstance((short) 5, (short) 2));
        vector.addElement(SignatureAndHashAlgorithm.getInstance((short) 6, (short) 2));
        vector.addElement(SignatureAndHashAlgorithm.getInstance((short) 3, (short) 3));
        vector.addElement(SignatureAndHashAlgorithm.getInstance((short) 3, (short) 1));
        vector.addElement(SignatureAndHashAlgorithm.getInstance((short) 3, (short) 2));
        vector.addElement(SignatureAndHashAlgorithm.getInstance((short) 2, (short) 3));
        vector.addElement(SignatureAndHashAlgorithm.getInstance((short) 2, (short) 1));
        vector.addElement(SignatureAndHashAlgorithm.getInstance((short) 2, (short) 2));
        return vector;
    }

    private static TlsHash createHash(TlsCrypto tlsCrypto, SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        return tlsCrypto.createHash(SignatureScheme.getCryptoHashAlgorithm(signatureAndHashAlgorithm));
    }

    private static TlsHash createHash(TlsCrypto tlsCrypto, short s) {
        return tlsCrypto.createHash(TlsCryptoUtils.getHash(s));
    }

    private static TlsKeyExchange createKeyExchangeClient(TlsClient tlsClient, int i) throws IOException {
        TlsKeyExchangeFactory keyExchangeFactory = tlsClient.getKeyExchangeFactory();
        if (i != 1) {
            if (i == 3 || i == 5) {
                return keyExchangeFactory.createDHEKeyExchangeClient(i, tlsClient.getDHGroupVerifier());
            }
            if (i == 7 || i == 9) {
                return keyExchangeFactory.createDHKeyExchange(i);
            }
            if (i != 11) {
                switch (i) {
                    case 13:
                    case 15:
                    case 24:
                        return keyExchangeFactory.createPSKKeyExchangeClient(i, tlsClient.getPSKIdentity(), null);
                    case 14:
                        return keyExchangeFactory.createPSKKeyExchangeClient(i, tlsClient.getPSKIdentity(), tlsClient.getDHGroupVerifier());
                    case 16:
                    case 18:
                        return keyExchangeFactory.createECDHKeyExchange(i);
                    case 17:
                    case 19:
                        return keyExchangeFactory.createECDHEKeyExchangeClient(i);
                    case 20:
                        return keyExchangeFactory.createECDHanonKeyExchangeClient(i);
                    case 21:
                    case 22:
                    case 23:
                        return keyExchangeFactory.createSRPKeyExchangeClient(i, tlsClient.getSRPIdentity(), tlsClient.getSRPConfigVerifier());
                    default:
                        throw new TlsFatalAlert((short) 80);
                }
            }
            return keyExchangeFactory.createDHanonKeyExchangeClient(i, tlsClient.getDHGroupVerifier());
        }
        return keyExchangeFactory.createRSAKeyExchange(i);
    }

    private static TlsKeyExchange createKeyExchangeServer(TlsServer tlsServer, int i) throws IOException {
        TlsKeyExchangeFactory keyExchangeFactory = tlsServer.getKeyExchangeFactory();
        if (i != 1) {
            if (i == 3 || i == 5) {
                return keyExchangeFactory.createDHEKeyExchangeServer(i, tlsServer.getDHConfig());
            }
            if (i == 7 || i == 9) {
                return keyExchangeFactory.createDHKeyExchange(i);
            }
            if (i != 11) {
                switch (i) {
                    case 13:
                    case 15:
                        return keyExchangeFactory.createPSKKeyExchangeServer(i, tlsServer.getPSKIdentityManager(), null, null);
                    case 14:
                        return keyExchangeFactory.createPSKKeyExchangeServer(i, tlsServer.getPSKIdentityManager(), tlsServer.getDHConfig(), null);
                    case 16:
                    case 18:
                        return keyExchangeFactory.createECDHKeyExchange(i);
                    case 17:
                    case 19:
                        return keyExchangeFactory.createECDHEKeyExchangeServer(i, tlsServer.getECDHConfig());
                    case 20:
                        return keyExchangeFactory.createECDHanonKeyExchangeServer(i, tlsServer.getECDHConfig());
                    case 21:
                    case 22:
                    case 23:
                        return keyExchangeFactory.createSRPKeyExchangeServer(i, tlsServer.getSRPLoginParameters());
                    case 24:
                        return keyExchangeFactory.createPSKKeyExchangeServer(i, tlsServer.getPSKIdentityManager(), null, tlsServer.getECDHConfig());
                    default:
                        throw new TlsFatalAlert((short) 80);
                }
            }
            return keyExchangeFactory.createDHanonKeyExchangeServer(i, tlsServer.getDHConfig());
        }
        return keyExchangeFactory.createRSAKeyExchange(i);
    }

    public static byte[] decodeOpaque16(byte[] bArr) throws IOException {
        return decodeOpaque16(bArr, 0);
    }

    public static byte[] decodeOpaque16(byte[] bArr, int i) throws IOException {
        if (bArr != null) {
            if (bArr.length >= 2) {
                int readUint16 = readUint16(bArr, 0);
                if (bArr.length != readUint16 + 2 || readUint16 < i) {
                    throw new TlsFatalAlert((short) 50);
                }
                return copyOfRangeExact(bArr, 2, bArr.length);
            }
            throw new TlsFatalAlert((short) 50);
        }
        throw new IllegalArgumentException("'buf' cannot be null");
    }

    public static byte[] decodeOpaque8(byte[] bArr) throws IOException {
        return decodeOpaque8(bArr, 0);
    }

    public static byte[] decodeOpaque8(byte[] bArr, int i) throws IOException {
        if (bArr != null) {
            if (bArr.length >= 1) {
                short readUint8 = readUint8(bArr, 0);
                if (bArr.length != readUint8 + 1 || readUint8 < i) {
                    throw new TlsFatalAlert((short) 50);
                }
                return copyOfRangeExact(bArr, 1, bArr.length);
            }
            throw new TlsFatalAlert((short) 50);
        }
        throw new IllegalArgumentException("'buf' cannot be null");
    }

    public static int decodeUint16(byte[] bArr) throws IOException {
        if (bArr != null) {
            if (bArr.length == 2) {
                return readUint16(bArr, 0);
            }
            throw new TlsFatalAlert((short) 50);
        }
        throw new IllegalArgumentException("'buf' cannot be null");
    }

    public static int[] decodeUint16ArrayWithUint8Length(byte[] bArr) throws IOException {
        if (bArr != null) {
            short readUint8 = readUint8(bArr, 0);
            if (bArr.length == readUint8 + 1 && (readUint8 & 1) == 0) {
                int i = readUint8 / 2;
                int[] iArr = new int[i];
                int i2 = 1;
                for (int i3 = 0; i3 < i; i3++) {
                    iArr[i3] = readUint16(bArr, i2);
                    i2 += 2;
                }
                return iArr;
            }
            throw new TlsFatalAlert((short) 50);
        }
        throw new IllegalArgumentException("'buf' cannot be null");
    }

    public static long decodeUint32(byte[] bArr) throws IOException {
        if (bArr != null) {
            if (bArr.length == 4) {
                return readUint32(bArr, 0);
            }
            throw new TlsFatalAlert((short) 50);
        }
        throw new IllegalArgumentException("'buf' cannot be null");
    }

    public static short decodeUint8(byte[] bArr) throws IOException {
        if (bArr != null) {
            if (bArr.length == 1) {
                return readUint8(bArr, 0);
            }
            throw new TlsFatalAlert((short) 50);
        }
        throw new IllegalArgumentException("'buf' cannot be null");
    }

    public static short[] decodeUint8ArrayWithUint8Length(byte[] bArr) throws IOException {
        if (bArr != null) {
            if (bArr.length >= 1) {
                int i = 0;
                int readUint8 = readUint8(bArr, 0);
                if (bArr.length == readUint8 + 1) {
                    short[] sArr = new short[readUint8];
                    while (i < readUint8) {
                        int i2 = i + 1;
                        sArr[i] = readUint8(bArr, i2);
                        i = i2;
                    }
                    return sArr;
                }
                throw new TlsFatalAlert((short) 50);
            }
            throw new TlsFatalAlert((short) 50);
        }
        throw new IllegalArgumentException("'buf' cannot be null");
    }

    static TlsSecret deriveSecret(int i, int i2, TlsSecret tlsSecret, String str, byte[] bArr) throws IOException {
        if (bArr.length == i2) {
            return TlsCryptoUtils.hkdfExpandLabel(tlsSecret, i, str, bArr, i2);
        }
        throw new TlsFatalAlert((short) 80);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TlsSecret deriveSecret(SecurityParameters securityParameters, TlsSecret tlsSecret, String str, byte[] bArr) throws IOException {
        return deriveSecret(securityParameters.getPRFCryptoHashAlgorithm(), securityParameters.getPRFHashLength(), tlsSecret, str, bArr);
    }

    public static byte[] encodeOpaque16(byte[] bArr) throws IOException {
        checkUint16(bArr.length);
        byte[] bArr2 = new byte[bArr.length + 2];
        writeUint16(bArr.length, bArr2, 0);
        System.arraycopy(bArr, 0, bArr2, 2, bArr.length);
        return bArr2;
    }

    public static byte[] encodeOpaque24(byte[] bArr) throws IOException {
        checkUint24(bArr.length);
        byte[] bArr2 = new byte[bArr.length + 3];
        writeUint24(bArr.length, bArr2, 0);
        System.arraycopy(bArr, 0, bArr2, 3, bArr.length);
        return bArr2;
    }

    public static byte[] encodeOpaque8(byte[] bArr) throws IOException {
        checkUint8(bArr.length);
        return Arrays.prepend(bArr, (byte) bArr.length);
    }

    public static void encodeSupportedSignatureAlgorithms(Vector vector, OutputStream outputStream) throws IOException {
        if (vector == null || vector.size() < 1 || vector.size() >= 32768) {
            throw new IllegalArgumentException("'supportedSignatureAlgorithms' must have length from 1 to (2^15 - 1)");
        }
        int size = vector.size() * 2;
        checkUint16(size);
        writeUint16(size, outputStream);
        for (int i = 0; i < vector.size(); i++) {
            SignatureAndHashAlgorithm signatureAndHashAlgorithm = (SignatureAndHashAlgorithm) vector.elementAt(i);
            if (signatureAndHashAlgorithm.getSignature() == 0) {
                throw new IllegalArgumentException("SignatureAlgorithm.anonymous MUST NOT appear in the signature_algorithms extension");
            }
            signatureAndHashAlgorithm.encode(outputStream);
        }
    }

    public static byte[] encodeUint16(int i) throws IOException {
        checkUint16(i);
        byte[] bArr = new byte[2];
        writeUint16(i, bArr, 0);
        return bArr;
    }

    public static byte[] encodeUint16ArrayWithUint16Length(int[] iArr) throws IOException {
        byte[] bArr = new byte[(iArr.length * 2) + 2];
        writeUint16ArrayWithUint16Length(iArr, bArr, 0);
        return bArr;
    }

    public static byte[] encodeUint16ArrayWithUint8Length(int[] iArr) throws IOException {
        byte[] bArr = new byte[(iArr.length * 2) + 1];
        writeUint16ArrayWithUint8Length(iArr, bArr, 0);
        return bArr;
    }

    public static byte[] encodeUint24(int i) throws IOException {
        checkUint24(i);
        byte[] bArr = new byte[3];
        writeUint24(i, bArr, 0);
        return bArr;
    }

    public static byte[] encodeUint32(long j) throws IOException {
        checkUint32(j);
        byte[] bArr = new byte[4];
        writeUint32(j, bArr, 0);
        return bArr;
    }

    public static byte[] encodeUint8(short s) throws IOException {
        checkUint8(s);
        byte[] bArr = new byte[1];
        writeUint8(s, bArr, 0);
        return bArr;
    }

    public static byte[] encodeUint8ArrayWithUint8Length(short[] sArr) throws IOException {
        byte[] bArr = new byte[sArr.length + 1];
        writeUint8ArrayWithUint8Length(sArr, bArr, 0);
        return bArr;
    }

    public static byte[] encodeVersion(ProtocolVersion protocolVersion) throws IOException {
        return new byte[]{(byte) protocolVersion.getMajorVersion(), (byte) protocolVersion.getMinorVersion()};
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TlsCredentialedSigner establish13ClientCredentials(TlsAuthentication tlsAuthentication, CertificateRequest certificateRequest) throws IOException {
        return validate13Credentials(tlsAuthentication.getClientCredentials(certificateRequest));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void establish13PhaseApplication(TlsContext tlsContext, byte[] bArr, RecordStream recordStream) throws IOException {
        SecurityParameters securityParametersHandshake = tlsContext.getSecurityParametersHandshake();
        TlsSecret masterSecret = securityParametersHandshake.getMasterSecret();
        establish13TrafficSecrets(tlsContext, bArr, masterSecret, "c ap traffic", "s ap traffic", recordStream);
        securityParametersHandshake.exporterMasterSecret = deriveSecret(securityParametersHandshake, masterSecret, "exp master", bArr);
    }

    static void establish13PhaseEarly(TlsContext tlsContext, byte[] bArr, RecordStream recordStream) throws IOException {
        SecurityParameters securityParametersHandshake = tlsContext.getSecurityParametersHandshake();
        TlsSecret earlySecret = securityParametersHandshake.getEarlySecret();
        if (recordStream != null) {
            establish13TrafficSecrets(tlsContext, bArr, earlySecret, "c e traffic", null, recordStream);
        }
        securityParametersHandshake.earlyExporterMasterSecret = deriveSecret(securityParametersHandshake, earlySecret, "e exp master", bArr);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void establish13PhaseHandshake(TlsContext tlsContext, byte[] bArr, RecordStream recordStream) throws IOException {
        SecurityParameters securityParametersHandshake = tlsContext.getSecurityParametersHandshake();
        establish13TrafficSecrets(tlsContext, bArr, securityParametersHandshake.getHandshakeSecret(), "c hs traffic", "s hs traffic", recordStream);
        securityParametersHandshake.baseKeyClient = securityParametersHandshake.getTrafficSecretClient();
        securityParametersHandshake.baseKeyServer = securityParametersHandshake.getTrafficSecretServer();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void establish13PhaseSecrets(TlsContext tlsContext, TlsSecret tlsSecret, TlsSecret tlsSecret2) throws IOException {
        TlsCrypto crypto = tlsContext.getCrypto();
        SecurityParameters securityParametersHandshake = tlsContext.getSecurityParametersHandshake();
        int pRFCryptoHashAlgorithm = securityParametersHandshake.getPRFCryptoHashAlgorithm();
        TlsSecret hkdfInit = crypto.hkdfInit(pRFCryptoHashAlgorithm);
        byte[] calculateHash = crypto.createHash(pRFCryptoHashAlgorithm).calculateHash();
        if (tlsSecret == null) {
            tlsSecret = crypto.hkdfInit(pRFCryptoHashAlgorithm).hkdfExtract(pRFCryptoHashAlgorithm, hkdfInit);
        }
        if (tlsSecret2 == null) {
            tlsSecret2 = hkdfInit;
        }
        TlsSecret hkdfExtract = deriveSecret(securityParametersHandshake, tlsSecret, "derived", calculateHash).hkdfExtract(pRFCryptoHashAlgorithm, tlsSecret2);
        if (tlsSecret2 != hkdfInit) {
            tlsSecret2.destroy();
        }
        TlsSecret hkdfExtract2 = deriveSecret(securityParametersHandshake, hkdfExtract, "derived", calculateHash).hkdfExtract(pRFCryptoHashAlgorithm, hkdfInit);
        securityParametersHandshake.earlySecret = tlsSecret;
        securityParametersHandshake.handshakeSecret = hkdfExtract;
        securityParametersHandshake.masterSecret = hkdfExtract2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TlsCredentialedSigner establish13ServerCredentials(TlsServer tlsServer) throws IOException {
        return validate13Credentials(tlsServer.getCredentials());
    }

    private static void establish13TrafficSecrets(TlsContext tlsContext, byte[] bArr, TlsSecret tlsSecret, String str, String str2, RecordStream recordStream) throws IOException {
        SecurityParameters securityParametersHandshake = tlsContext.getSecurityParametersHandshake();
        securityParametersHandshake.trafficSecretClient = deriveSecret(securityParametersHandshake, tlsSecret, str, bArr);
        if (str2 != null) {
            securityParametersHandshake.trafficSecretServer = deriveSecret(securityParametersHandshake, tlsSecret, str2, bArr);
        }
        recordStream.setPendingCipher(initCipher(tlsContext));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TlsCredentials establishClientCredentials(TlsAuthentication tlsAuthentication, CertificateRequest certificateRequest) throws IOException {
        return validateCredentials(tlsAuthentication.getClientCredentials(certificateRequest));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void establishClientSigAlgs(SecurityParameters securityParameters, Hashtable hashtable) throws IOException {
        securityParameters.clientSigAlgs = TlsExtensionsUtils.getSignatureAlgorithmsExtension(hashtable);
        securityParameters.clientSigAlgsCert = TlsExtensionsUtils.getSignatureAlgorithmsCertExtension(hashtable);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TlsCredentials establishServerCredentials(TlsServer tlsServer) throws IOException {
        return validateCredentials(tlsServer.getCredentials());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void establishServerSigAlgs(SecurityParameters securityParameters, CertificateRequest certificateRequest) throws IOException {
        securityParameters.clientCertTypes = certificateRequest.getCertificateTypes();
        securityParameters.serverSigAlgs = certificateRequest.getSupportedSignatureAlgorithms();
        securityParameters.serverSigAlgsCert = certificateRequest.getSupportedSignatureAlgorithmsCert();
        if (securityParameters.getServerSigAlgsCert() == null) {
            securityParameters.serverSigAlgsCert = securityParameters.getServerSigAlgs();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static DigitallySigned generate13CertificateVerify(TlsContext tlsContext, TlsCredentialedSigner tlsCredentialedSigner, TlsHandshakeHash tlsHandshakeHash) throws IOException {
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = tlsCredentialedSigner.getSignatureAndHashAlgorithm();
        if (signatureAndHashAlgorithm != null) {
            return new DigitallySigned(signatureAndHashAlgorithm, generate13CertificateVerify(tlsContext.getCrypto(), tlsCredentialedSigner, tlsContext.isServer() ? "TLS 1.3, server CertificateVerify" : "TLS 1.3, client CertificateVerify", tlsHandshakeHash, signatureAndHashAlgorithm));
        }
        throw new TlsFatalAlert((short) 80);
    }

    private static byte[] generate13CertificateVerify(TlsCrypto tlsCrypto, TlsCredentialedSigner tlsCredentialedSigner, String str, TlsHandshakeHash tlsHandshakeHash, SignatureAndHashAlgorithm signatureAndHashAlgorithm) throws IOException {
        TlsStreamSigner streamSigner = tlsCredentialedSigner.getStreamSigner();
        byte[] certificateVerifyHeader = getCertificateVerifyHeader(str);
        byte[] currentPRFHash = getCurrentPRFHash(tlsHandshakeHash);
        if (streamSigner != null) {
            OutputStream outputStream = streamSigner.getOutputStream();
            outputStream.write(certificateVerifyHeader, 0, certificateVerifyHeader.length);
            outputStream.write(currentPRFHash, 0, currentPRFHash.length);
            return streamSigner.getSignature();
        }
        TlsHash createHash = createHash(tlsCrypto, signatureAndHashAlgorithm);
        createHash.update(certificateVerifyHeader, 0, certificateVerifyHeader.length);
        createHash.update(currentPRFHash, 0, currentPRFHash.length);
        return tlsCredentialedSigner.generateRawSignature(createHash.calculateHash());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static DigitallySigned generateCertificateVerifyClient(TlsClientContext tlsClientContext, TlsCredentialedSigner tlsCredentialedSigner, SignatureAndHashAlgorithm signatureAndHashAlgorithm, TlsStreamSigner tlsStreamSigner, TlsHandshakeHash tlsHandshakeHash) throws IOException {
        byte[] generateRawSignature;
        SecurityParameters securityParametersHandshake = tlsClientContext.getSecurityParametersHandshake();
        if (isTLSv13(securityParametersHandshake.getNegotiatedVersion())) {
            throw new TlsFatalAlert((short) 80);
        }
        if (tlsStreamSigner != null) {
            tlsHandshakeHash.copyBufferTo(tlsStreamSigner.getOutputStream());
            generateRawSignature = tlsStreamSigner.getSignature();
        } else {
            generateRawSignature = tlsCredentialedSigner.generateRawSignature(signatureAndHashAlgorithm == null ? securityParametersHandshake.getSessionHash() : tlsHandshakeHash.getFinalHash(SignatureScheme.getCryptoHashAlgorithm(signatureAndHashAlgorithm)));
        }
        return new DigitallySigned(signatureAndHashAlgorithm, generateRawSignature);
    }

    public static TlsSecret generateEncryptedPreMasterSecret(TlsContext tlsContext, TlsEncryptor tlsEncryptor, OutputStream outputStream) throws IOException {
        TlsSecret generateRSAPreMasterSecret = tlsContext.getCrypto().generateRSAPreMasterSecret(tlsContext.getRSAPreMasterSecretVersion());
        writeEncryptedPMS(tlsContext, generateRSAPreMasterSecret.encrypt(tlsEncryptor), outputStream);
        return generateRSAPreMasterSecret;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void generateServerKeyExchangeSignature(TlsContext tlsContext, TlsCredentialedSigner tlsCredentialedSigner, byte[] bArr, DigestInputBuffer digestInputBuffer) throws IOException {
        byte[] generateRawSignature;
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = getSignatureAndHashAlgorithm(tlsContext.getServerVersion(), tlsCredentialedSigner);
        TlsStreamSigner streamSigner = tlsCredentialedSigner.getStreamSigner();
        if (streamSigner != null) {
            sendSignatureInput(tlsContext, bArr, digestInputBuffer, streamSigner.getOutputStream());
            generateRawSignature = streamSigner.getSignature();
        } else {
            generateRawSignature = tlsCredentialedSigner.generateRawSignature(calculateSignatureHash(tlsContext, signatureAndHashAlgorithm, bArr, digestInputBuffer));
        }
        new DigitallySigned(signatureAndHashAlgorithm, generateRawSignature).encode(digestInputBuffer);
    }

    static SignatureAndHashAlgorithm getCertSigAndHashAlg(TlsCertificate tlsCertificate, TlsCertificate tlsCertificate2) throws IOException {
        String sigAlgOID = tlsCertificate.getSigAlgOID();
        if (sigAlgOID != null) {
            if (PKCSObjectIdentifiers.id_RSASSA_PSS.getId().equals(sigAlgOID)) {
                RSASSAPSSparams rSASSAPSSparams = RSASSAPSSparams.getInstance(tlsCertificate.getSigAlgParams());
                if (rSASSAPSSparams != null) {
                    ASN1ObjectIdentifier algorithm = rSASSAPSSparams.getHashAlgorithm().getAlgorithm();
                    if (NISTObjectIdentifiers.id_sha256.equals((ASN1Primitive) algorithm)) {
                        if (tlsCertificate2.supportsSignatureAlgorithmCA((short) 9)) {
                            return SignatureAndHashAlgorithm.rsa_pss_pss_sha256;
                        }
                        if (tlsCertificate2.supportsSignatureAlgorithmCA((short) 4)) {
                            return SignatureAndHashAlgorithm.rsa_pss_rsae_sha256;
                        }
                        return null;
                    } else if (NISTObjectIdentifiers.id_sha384.equals((ASN1Primitive) algorithm)) {
                        if (tlsCertificate2.supportsSignatureAlgorithmCA((short) 10)) {
                            return SignatureAndHashAlgorithm.rsa_pss_pss_sha384;
                        }
                        if (tlsCertificate2.supportsSignatureAlgorithmCA((short) 5)) {
                            return SignatureAndHashAlgorithm.rsa_pss_rsae_sha384;
                        }
                        return null;
                    } else if (NISTObjectIdentifiers.id_sha512.equals((ASN1Primitive) algorithm)) {
                        if (tlsCertificate2.supportsSignatureAlgorithmCA((short) 11)) {
                            return SignatureAndHashAlgorithm.rsa_pss_pss_sha512;
                        }
                        if (tlsCertificate2.supportsSignatureAlgorithmCA((short) 6)) {
                            return SignatureAndHashAlgorithm.rsa_pss_rsae_sha512;
                        }
                        return null;
                    } else {
                        return null;
                    }
                }
                return null;
            }
            return (SignatureAndHashAlgorithm) CERT_SIG_ALG_OIDS.get(sigAlgOID);
        }
        return null;
    }

    private static byte[] getCertificateVerifyHeader(String str) {
        int length = str.length();
        int i = length + 64;
        byte[] bArr = new byte[length + 65];
        for (int i2 = 0; i2 < 64; i2++) {
            bArr[i2] = 32;
        }
        for (int i3 = 0; i3 < length; i3++) {
            bArr[i3 + 64] = (byte) str.charAt(i3);
        }
        bArr[i] = 0;
        return bArr;
    }

    public static int getCipherType(int i) {
        return getEncryptionAlgorithmType(getEncryptionAlgorithm(i));
    }

    public static int getCommonCipherSuite13(ProtocolVersion protocolVersion, int[] iArr, int[] iArr2, boolean z) {
        if (z) {
            iArr2 = iArr;
            iArr = iArr2;
        }
        for (int i : iArr) {
            if (Arrays.contains(iArr2, i) && isValidVersionForCipherSuite(i, protocolVersion)) {
                return i;
            }
        }
        return -1;
    }

    public static int[] getCommonCipherSuites(int[] iArr, int[] iArr2, boolean z) {
        if (z) {
            iArr2 = iArr;
            iArr = iArr2;
        }
        int min = Math.min(iArr.length, iArr2.length);
        int[] iArr3 = new int[min];
        int i = 0;
        for (int i2 : iArr) {
            if (!contains(iArr3, 0, i, i2) && Arrays.contains(iArr2, i2)) {
                iArr3[i] = i2;
                i++;
            }
        }
        return i < min ? Arrays.copyOf(iArr3, i) : iArr3;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] getCurrentPRFHash(TlsHandshakeHash tlsHandshakeHash) {
        return tlsHandshakeHash.forkPRFHash().calculateHash();
    }

    public static Vector getDefaultDSSSignatureAlgorithms() {
        return getDefaultSignatureAlgorithms((short) 2);
    }

    public static Vector getDefaultECDSASignatureAlgorithms() {
        return getDefaultSignatureAlgorithms((short) 3);
    }

    public static Vector getDefaultRSASignatureAlgorithms() {
        return getDefaultSignatureAlgorithms((short) 1);
    }

    public static SignatureAndHashAlgorithm getDefaultSignatureAlgorithm(short s) {
        if (s == 1 || s == 2 || s == 3) {
            return SignatureAndHashAlgorithm.getInstance((short) 2, s);
        }
        return null;
    }

    public static Vector getDefaultSignatureAlgorithms(short s) {
        SignatureAndHashAlgorithm defaultSignatureAlgorithm = getDefaultSignatureAlgorithm(s);
        return defaultSignatureAlgorithm == null ? new Vector() : vectorOfOne(defaultSignatureAlgorithm);
    }

    public static Vector getDefaultSupportedSignatureAlgorithms(TlsContext tlsContext) {
        return getSupportedSignatureAlgorithms(tlsContext, DEFAULT_SUPPORTED_SIG_ALGS);
    }

    /*  JADX ERROR: JadxRuntimeException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxRuntimeException: Failed to find switch 'out' block
        	at jadx.core.dex.visitors.regions.RegionMaker.processSwitch(RegionMaker.java:817)
        	at jadx.core.dex.visitors.regions.RegionMaker.traverse(RegionMaker.java:160)
        	at jadx.core.dex.visitors.regions.RegionMaker.makeRegion(RegionMaker.java:94)
        	at jadx.core.dex.visitors.regions.RegionMaker.processSwitch(RegionMaker.java:856)
        	at jadx.core.dex.visitors.regions.RegionMaker.traverse(RegionMaker.java:160)
        	at jadx.core.dex.visitors.regions.RegionMaker.makeRegion(RegionMaker.java:94)
        	at jadx.core.dex.visitors.regions.RegionMaker.processSwitch(RegionMaker.java:856)
        	at jadx.core.dex.visitors.regions.RegionMaker.traverse(RegionMaker.java:160)
        	at jadx.core.dex.visitors.regions.RegionMaker.makeRegion(RegionMaker.java:94)
        	at jadx.core.dex.visitors.regions.RegionMaker.processSwitch(RegionMaker.java:856)
        	at jadx.core.dex.visitors.regions.RegionMaker.traverse(RegionMaker.java:160)
        	at jadx.core.dex.visitors.regions.RegionMaker.makeRegion(RegionMaker.java:94)
        	at jadx.core.dex.visitors.regions.RegionMaker.processSwitch(RegionMaker.java:856)
        	at jadx.core.dex.visitors.regions.RegionMaker.traverse(RegionMaker.java:160)
        	at jadx.core.dex.visitors.regions.RegionMaker.makeRegion(RegionMaker.java:94)
        	at jadx.core.dex.visitors.regions.RegionMaker.processSwitch(RegionMaker.java:856)
        	at jadx.core.dex.visitors.regions.RegionMaker.traverse(RegionMaker.java:160)
        	at jadx.core.dex.visitors.regions.RegionMaker.makeRegion(RegionMaker.java:94)
        	at jadx.core.dex.visitors.regions.RegionMaker.processSwitch(RegionMaker.java:856)
        	at jadx.core.dex.visitors.regions.RegionMaker.traverse(RegionMaker.java:160)
        	at jadx.core.dex.visitors.regions.RegionMaker.makeRegion(RegionMaker.java:94)
        	at jadx.core.dex.visitors.regions.RegionMaker.processSwitch(RegionMaker.java:856)
        	at jadx.core.dex.visitors.regions.RegionMaker.traverse(RegionMaker.java:160)
        	at jadx.core.dex.visitors.regions.RegionMaker.makeRegion(RegionMaker.java:94)
        	at jadx.core.dex.visitors.regions.RegionMakerVisitor.visit(RegionMakerVisitor.java:52)
        */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0057 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0069 A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static int getEncryptionAlgorithm(int r1) {
        /*
            r0 = 0
            switch(r1) {
                case 2: goto L69;
                case 10: goto L67;
                case 13: goto L67;
                case 16: goto L67;
                case 19: goto L67;
                case 22: goto L67;
                case 27: goto L67;
                case 147: goto L67;
                case 148: goto L64;
                case 149: goto L61;
                case 150: goto L5e;
                case 151: goto L5e;
                case 152: goto L5e;
                case 153: goto L5e;
                case 154: goto L5e;
                case 155: goto L5e;
                case 156: goto L5b;
                case 157: goto L58;
                case 158: goto L5b;
                case 159: goto L58;
                case 160: goto L5b;
                case 161: goto L58;
                case 162: goto L5b;
                case 163: goto L58;
                case 164: goto L5b;
                case 165: goto L58;
                case 166: goto L5b;
                case 167: goto L58;
                case 168: goto L5b;
                case 169: goto L58;
                case 170: goto L5b;
                case 171: goto L58;
                case 172: goto L5b;
                case 173: goto L58;
                case 174: goto L64;
                case 175: goto L61;
                case 176: goto L57;
                case 177: goto L57;
                case 178: goto L64;
                case 179: goto L61;
                case 180: goto L57;
                case 181: goto L57;
                case 182: goto L64;
                case 183: goto L61;
                case 184: goto L57;
                case 185: goto L57;
                case 186: goto L54;
                case 187: goto L54;
                case 188: goto L54;
                case 189: goto L54;
                case 190: goto L54;
                case 191: goto L54;
                case 192: goto L51;
                case 193: goto L51;
                case 194: goto L51;
                case 195: goto L51;
                case 196: goto L51;
                case 197: goto L51;
                case 198: goto L4e;
                case 199: goto L4b;
                case 49153: goto L69;
                case 49170: goto L67;
                case 49171: goto L64;
                case 49172: goto L61;
                case 49173: goto L69;
                case 49175: goto L67;
                case 49176: goto L64;
                case 49177: goto L61;
                case 49178: goto L67;
                case 49179: goto L67;
                case 49180: goto L67;
                case 49181: goto L64;
                case 49182: goto L64;
                case 49183: goto L64;
                case 49184: goto L61;
                case 49185: goto L61;
                case 49186: goto L61;
                case 49187: goto L64;
                case 49188: goto L61;
                case 49189: goto L64;
                case 49190: goto L61;
                case 49191: goto L64;
                case 49192: goto L61;
                case 49193: goto L64;
                case 49194: goto L61;
                case 49195: goto L5b;
                case 49196: goto L58;
                case 49197: goto L5b;
                case 49198: goto L58;
                case 49199: goto L5b;
                case 49200: goto L58;
                case 49201: goto L5b;
                case 49202: goto L58;
                case 49204: goto L67;
                case 49205: goto L64;
                case 49206: goto L61;
                case 49207: goto L64;
                case 49208: goto L61;
                case 49209: goto L69;
                case 49210: goto L57;
                case 49211: goto L57;
                case 49212: goto L48;
                case 49213: goto L45;
                case 49214: goto L48;
                case 49215: goto L45;
                case 49216: goto L48;
                case 49217: goto L45;
                case 49218: goto L48;
                case 49219: goto L45;
                case 49220: goto L48;
                case 49221: goto L45;
                case 49222: goto L48;
                case 49223: goto L45;
                case 49224: goto L48;
                case 49225: goto L45;
                case 49226: goto L48;
                case 49227: goto L45;
                case 49228: goto L48;
                case 49229: goto L45;
                case 49230: goto L48;
                case 49231: goto L45;
                case 49232: goto L42;
                case 49233: goto L3f;
                case 49234: goto L42;
                case 49235: goto L3f;
                case 49236: goto L42;
                case 49237: goto L3f;
                case 49238: goto L42;
                case 49239: goto L3f;
                case 49240: goto L42;
                case 49241: goto L3f;
                case 49242: goto L42;
                case 49243: goto L3f;
                case 49244: goto L42;
                case 49245: goto L3f;
                case 49246: goto L42;
                case 49247: goto L3f;
                case 49248: goto L42;
                case 49249: goto L3f;
                case 49250: goto L42;
                case 49251: goto L3f;
                case 49252: goto L48;
                case 49253: goto L45;
                case 49254: goto L48;
                case 49255: goto L45;
                case 49256: goto L48;
                case 49257: goto L45;
                case 49258: goto L42;
                case 49259: goto L3f;
                case 49260: goto L42;
                case 49261: goto L3f;
                case 49262: goto L42;
                case 49263: goto L3f;
                case 49264: goto L48;
                case 49265: goto L45;
                case 49266: goto L54;
                case 49267: goto L51;
                case 49268: goto L54;
                case 49269: goto L51;
                case 49270: goto L54;
                case 49271: goto L51;
                case 49272: goto L54;
                case 49273: goto L51;
                case 49274: goto L3c;
                case 49275: goto L39;
                case 49276: goto L3c;
                case 49277: goto L39;
                case 49278: goto L3c;
                case 49279: goto L39;
                case 49280: goto L3c;
                case 49281: goto L39;
                case 49282: goto L3c;
                case 49283: goto L39;
                case 49284: goto L3c;
                case 49285: goto L39;
                case 49286: goto L3c;
                case 49287: goto L39;
                case 49288: goto L3c;
                case 49289: goto L39;
                case 49290: goto L3c;
                case 49291: goto L39;
                case 49292: goto L3c;
                case 49293: goto L39;
                case 49294: goto L3c;
                case 49295: goto L39;
                case 49296: goto L3c;
                case 49297: goto L39;
                case 49298: goto L3c;
                case 49299: goto L39;
                case 49300: goto L54;
                case 49301: goto L51;
                case 49302: goto L54;
                case 49303: goto L51;
                case 49304: goto L54;
                case 49305: goto L51;
                case 49306: goto L54;
                case 49307: goto L51;
                case 49308: goto L36;
                case 49309: goto L33;
                case 49310: goto L36;
                case 49311: goto L33;
                case 49312: goto L30;
                case 49313: goto L2d;
                case 49314: goto L30;
                case 49315: goto L2d;
                case 49316: goto L36;
                case 49317: goto L33;
                case 49318: goto L36;
                case 49319: goto L33;
                case 49320: goto L30;
                case 49321: goto L2d;
                case 49322: goto L30;
                case 49323: goto L2d;
                case 49324: goto L36;
                case 49325: goto L33;
                case 49326: goto L30;
                case 49327: goto L2d;
                case 49408: goto L2a;
                case 49409: goto L27;
                case 49410: goto L24;
                case 52392: goto L21;
                case 52393: goto L21;
                case 52394: goto L21;
                case 52395: goto L21;
                case 52396: goto L21;
                case 52397: goto L21;
                case 52398: goto L21;
                case 53249: goto L5b;
                case 53250: goto L58;
                case 53251: goto L30;
                case 53253: goto L36;
                default: goto L4;
            }
        L4:
            switch(r1) {
                case 44: goto L69;
                case 45: goto L69;
                case 46: goto L69;
                case 47: goto L64;
                case 48: goto L64;
                case 49: goto L64;
                case 50: goto L64;
                case 51: goto L64;
                case 52: goto L64;
                case 53: goto L61;
                case 54: goto L61;
                case 55: goto L61;
                case 56: goto L61;
                case 57: goto L61;
                case 58: goto L61;
                case 59: goto L57;
                case 60: goto L64;
                case 61: goto L61;
                case 62: goto L64;
                case 63: goto L64;
                case 64: goto L64;
                case 65: goto L54;
                case 66: goto L54;
                case 67: goto L54;
                case 68: goto L54;
                case 69: goto L54;
                case 70: goto L54;
                default: goto L7;
            }
        L7:
            switch(r1) {
                case 103: goto L64;
                case 104: goto L61;
                case 105: goto L61;
                case 106: goto L61;
                case 107: goto L61;
                case 108: goto L64;
                case 109: goto L61;
                default: goto La;
            }
        La:
            switch(r1) {
                case 132: goto L51;
                case 133: goto L51;
                case 134: goto L51;
                case 135: goto L51;
                case 136: goto L51;
                case 137: goto L51;
                default: goto Ld;
            }
        Ld:
            switch(r1) {
                case 139: goto L67;
                case 140: goto L64;
                case 141: goto L61;
                default: goto L10;
            }
        L10:
            switch(r1) {
                case 143: goto L67;
                case 144: goto L64;
                case 145: goto L61;
                default: goto L13;
            }
        L13:
            switch(r1) {
                case 4865: goto L5b;
                case 4866: goto L58;
                case 4867: goto L21;
                case 4868: goto L36;
                case 4869: goto L30;
                default: goto L16;
            }
        L16:
            switch(r1) {
                case 49155: goto L67;
                case 49156: goto L64;
                case 49157: goto L61;
                case 49158: goto L69;
                default: goto L19;
            }
        L19:
            switch(r1) {
                case 49160: goto L67;
                case 49161: goto L64;
                case 49162: goto L61;
                case 49163: goto L69;
                default: goto L1c;
            }
        L1c:
            switch(r1) {
                case 49165: goto L67;
                case 49166: goto L64;
                case 49167: goto L61;
                case 49168: goto L69;
                default: goto L1f;
            }
        L1f:
            r1 = -1
            return r1
        L21:
            r1 = 21
            return r1
        L24:
            r1 = 31
            return r1
        L27:
            r1 = 30
            return r1
        L2a:
            r1 = 29
            return r1
        L2d:
            r1 = 18
            return r1
        L30:
            r1 = 16
            return r1
        L33:
            r1 = 17
            return r1
        L36:
            r1 = 15
            return r1
        L39:
            r1 = 20
            return r1
        L3c:
            r1 = 19
            return r1
        L3f:
            r1 = 25
            return r1
        L42:
            r1 = 24
            return r1
        L45:
            r1 = 23
            return r1
        L48:
            r1 = 22
            return r1
        L4b:
            r1 = 26
            return r1
        L4e:
            r1 = 27
            return r1
        L51:
            r1 = 13
            return r1
        L54:
            r1 = 12
            return r1
        L57:
            return r0
        L58:
            r1 = 11
            return r1
        L5b:
            r1 = 10
            return r1
        L5e:
            r1 = 14
            return r1
        L61:
            r1 = 9
            return r1
        L64:
            r1 = 8
            return r1
        L67:
            r1 = 7
            return r1
        L69:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.TlsUtils.getEncryptionAlgorithm(int):int");
    }

    public static int getEncryptionAlgorithmType(int i) {
        switch (i) {
            case 0:
            case 1:
            case 2:
            case 29:
            case 30:
            case 31:
                return 0;
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
            case 12:
            case 13:
            case 14:
            case 22:
            case 23:
            case 28:
                return 1;
            case 10:
            case 11:
            case 15:
            case 16:
            case 17:
            case 18:
            case 19:
            case 20:
            case 21:
            case 24:
            case 25:
            case 26:
            case 27:
                return 2;
            default:
                return -1;
        }
    }

    public static byte[] getExtensionData(Hashtable hashtable, Integer num) {
        if (hashtable == null) {
            return null;
        }
        return (byte[]) hashtable.get(num);
    }

    public static int getKeyExchangeAlgorithm(int i) {
        switch (i) {
            case 2:
            case 10:
            case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA /* 150 */:
            case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256 /* 156 */:
            case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384 /* 157 */:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 /* 186 */:
            case 192:
            case CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256 /* 49212 */:
            case CipherSuite.TLS_RSA_WITH_ARIA_256_CBC_SHA384 /* 49213 */:
            case CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256 /* 49232 */:
            case CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384 /* 49233 */:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 /* 49274 */:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 /* 49275 */:
            case CipherSuite.TLS_RSA_WITH_AES_128_CCM /* 49308 */:
            case CipherSuite.TLS_RSA_WITH_AES_256_CCM /* 49309 */:
            case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8 /* 49312 */:
            case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8 /* 49313 */:
                return 1;
            case 13:
            case CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA /* 151 */:
            case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256 /* 164 */:
            case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384 /* 165 */:
            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 /* 187 */:
            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 /* 193 */:
            case CipherSuite.TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 /* 49214 */:
            case CipherSuite.TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 /* 49215 */:
            case CipherSuite.TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 /* 49240 */:
            case CipherSuite.TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 /* 49241 */:
            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 /* 49282 */:
            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 /* 49283 */:
                return 7;
            case 16:
            case CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA /* 152 */:
            case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256 /* 160 */:
            case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384 /* 161 */:
            case 188:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 /* 194 */:
            case CipherSuite.TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 /* 49216 */:
            case CipherSuite.TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 /* 49217 */:
            case CipherSuite.TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 /* 49236 */:
            case CipherSuite.TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 /* 49237 */:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 /* 49278 */:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 /* 49279 */:
                return 9;
            case 19:
            case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA /* 153 */:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 /* 162 */:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 /* 163 */:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 /* 189 */:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 /* 195 */:
            case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 /* 49218 */:
            case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 /* 49219 */:
            case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 /* 49238 */:
            case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 /* 49239 */:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 /* 49280 */:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 /* 49281 */:
                return 3;
            case 22:
            case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA /* 154 */:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 /* 158 */:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 /* 159 */:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 /* 190 */:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 /* 196 */:
            case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 /* 49220 */:
            case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 /* 49221 */:
            case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 /* 49234 */:
            case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 /* 49235 */:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 /* 49276 */:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 /* 49277 */:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM /* 49310 */:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM /* 49311 */:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8 /* 49314 */:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8 /* 49315 */:
            case CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 /* 52394 */:
                return 5;
            case 27:
            case CipherSuite.TLS_DH_anon_WITH_SEED_CBC_SHA /* 155 */:
            case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256 /* 166 */:
            case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384 /* 167 */:
            case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 /* 191 */:
            case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 /* 197 */:
            case CipherSuite.TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 /* 49222 */:
            case CipherSuite.TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 /* 49223 */:
            case CipherSuite.TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 /* 49242 */:
            case CipherSuite.TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 /* 49243 */:
            case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 /* 49284 */:
            case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 /* 49285 */:
                return 11;
            case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA /* 147 */:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA /* 148 */:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA /* 149 */:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 /* 172 */:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 /* 173 */:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 /* 182 */:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 /* 183 */:
            case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA256 /* 184 */:
            case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384 /* 185 */:
            case CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 /* 49256 */:
            case CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 /* 49257 */:
            case CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 /* 49262 */:
            case CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 /* 49263 */:
            case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 /* 49298 */:
            case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 /* 49299 */:
            case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 /* 49304 */:
            case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 /* 49305 */:
            case CipherSuite.TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 /* 52398 */:
                return 15;
            case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256 /* 168 */:
            case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384 /* 169 */:
            case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256 /* 174 */:
            case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384 /* 175 */:
            case CipherSuite.TLS_PSK_WITH_NULL_SHA256 /* 176 */:
            case CipherSuite.TLS_PSK_WITH_NULL_SHA384 /* 177 */:
            case CipherSuite.TLS_PSK_WITH_ARIA_128_CBC_SHA256 /* 49252 */:
            case CipherSuite.TLS_PSK_WITH_ARIA_256_CBC_SHA384 /* 49253 */:
            case CipherSuite.TLS_PSK_WITH_ARIA_128_GCM_SHA256 /* 49258 */:
            case CipherSuite.TLS_PSK_WITH_ARIA_256_GCM_SHA384 /* 49259 */:
            case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 /* 49294 */:
            case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 /* 49295 */:
            case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 /* 49300 */:
            case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 /* 49301 */:
            case CipherSuite.TLS_PSK_WITH_AES_128_CCM /* 49316 */:
            case CipherSuite.TLS_PSK_WITH_AES_256_CCM /* 49317 */:
            case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8 /* 49320 */:
            case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8 /* 49321 */:
            case CipherSuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 /* 52395 */:
                return 13;
            case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 /* 170 */:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 /* 171 */:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 /* 178 */:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 /* 179 */:
            case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256 /* 180 */:
            case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384 /* 181 */:
            case CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 /* 49254 */:
            case CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 /* 49255 */:
            case CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 /* 49260 */:
            case CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 /* 49261 */:
            case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 /* 49296 */:
            case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 /* 49297 */:
            case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 /* 49302 */:
            case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 /* 49303 */:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM /* 49318 */:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM /* 49319 */:
            case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8 /* 49322 */:
            case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8 /* 49323 */:
            case CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 /* 52397 */:
                return 14;
            case CipherSuite.TLS_SM4_GCM_SM3 /* 198 */:
            case CipherSuite.TLS_SM4_CCM_SM3 /* 199 */:
                return 0;
            case CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA /* 49153 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 /* 49189 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 /* 49190 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 /* 49197 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 /* 49198 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 /* 49226 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 /* 49227 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 /* 49246 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 /* 49247 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 /* 49268 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 /* 49269 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 /* 49288 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 /* 49289 */:
                return 16;
            case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA /* 49170 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA /* 49171 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA /* 49172 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 /* 49191 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 /* 49192 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 /* 49199 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 /* 49200 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 /* 49228 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 /* 49229 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 /* 49248 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 /* 49249 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 /* 49270 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 /* 49271 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 /* 49290 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 /* 49291 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 /* 52392 */:
                return 19;
            case CipherSuite.TLS_ECDH_anon_WITH_NULL_SHA /* 49173 */:
            case CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA /* 49175 */:
            case CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA /* 49176 */:
            case CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA /* 49177 */:
                return 20;
            case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA /* 49178 */:
            case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA /* 49181 */:
            case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA /* 49184 */:
                return 21;
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA /* 49179 */:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA /* 49182 */:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA /* 49185 */:
                return 23;
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA /* 49180 */:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA /* 49183 */:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA /* 49186 */:
                return 22;
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 /* 49187 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 /* 49188 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 /* 49195 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 /* 49196 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 /* 49224 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 /* 49225 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 /* 49244 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 /* 49245 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 /* 49266 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 /* 49267 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 /* 49286 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 /* 49287 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM /* 49324 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM /* 49325 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 /* 49326 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 /* 49327 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 /* 52393 */:
                return 17;
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 /* 49193 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 /* 49194 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 /* 49201 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 /* 49202 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 /* 49230 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 /* 49231 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 /* 49250 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 /* 49251 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 /* 49272 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 /* 49273 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 /* 49292 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 /* 49293 */:
                return 18;
            case CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA /* 49204 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA /* 49205 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA /* 49206 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 /* 49207 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 /* 49208 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA /* 49209 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256 /* 49210 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384 /* 49211 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 /* 49264 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 /* 49265 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 /* 49306 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 /* 49307 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 /* 52396 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 /* 53249 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 /* 53250 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 /* 53251 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 /* 53253 */:
                return 24;
            case CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC /* 49408 */:
            case CipherSuite.TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC /* 49409 */:
            case CipherSuite.TLS_GOSTR341112_256_WITH_28147_CNT_IMIT /* 49410 */:
                return 26;
            default:
                switch (i) {
                    case 44:
                        return 13;
                    case 45:
                        return 14;
                    case 46:
                        return 15;
                    case 47:
                    case 53:
                    case 59:
                    case 60:
                    case 61:
                    case 65:
                        return 1;
                    case 48:
                    case 54:
                    case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256 /* 62 */:
                    case 66:
                        return 7;
                    case 49:
                    case 55:
                    case 63:
                    case 67:
                        return 9;
                    case 50:
                    case 56:
                    case 64:
                    case 68:
                        return 3;
                    case 51:
                    case 57:
                    case 69:
                        return 5;
                    case 52:
                    case 58:
                    case 70:
                        return 11;
                    default:
                        switch (i) {
                            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 /* 103 */:
                            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 /* 107 */:
                                return 5;
                            case 104:
                                return 7;
                            case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256 /* 105 */:
                                return 9;
                            case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 /* 106 */:
                                return 3;
                            case 108:
                            case 109:
                                return 11;
                            default:
                                switch (i) {
                                    case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA /* 132 */:
                                        return 1;
                                    case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA /* 133 */:
                                        return 7;
                                    case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA /* 134 */:
                                        return 9;
                                    case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA /* 135 */:
                                        return 3;
                                    case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA /* 136 */:
                                        return 5;
                                    case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA /* 137 */:
                                        return 11;
                                    default:
                                        switch (i) {
                                            case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA /* 139 */:
                                            case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA /* 140 */:
                                            case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA /* 141 */:
                                                return 13;
                                            default:
                                                switch (i) {
                                                    case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA /* 143 */:
                                                    case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA /* 144 */:
                                                    case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA /* 145 */:
                                                        return 14;
                                                    default:
                                                        switch (i) {
                                                            case CipherSuite.TLS_AES_128_GCM_SHA256 /* 4865 */:
                                                            case CipherSuite.TLS_AES_256_GCM_SHA384 /* 4866 */:
                                                            case CipherSuite.TLS_CHACHA20_POLY1305_SHA256 /* 4867 */:
                                                            case CipherSuite.TLS_AES_128_CCM_SHA256 /* 4868 */:
                                                            case CipherSuite.TLS_AES_128_CCM_8_SHA256 /* 4869 */:
                                                                return 0;
                                                            default:
                                                                switch (i) {
                                                                    case CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA /* 49155 */:
                                                                    case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA /* 49156 */:
                                                                    case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA /* 49157 */:
                                                                        return 16;
                                                                    case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA /* 49158 */:
                                                                        return 17;
                                                                    default:
                                                                        switch (i) {
                                                                            case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA /* 49160 */:
                                                                            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA /* 49161 */:
                                                                            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA /* 49162 */:
                                                                                return 17;
                                                                            case CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA /* 49163 */:
                                                                                return 18;
                                                                            default:
                                                                                switch (i) {
                                                                                    case CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA /* 49165 */:
                                                                                    case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA /* 49166 */:
                                                                                    case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA /* 49167 */:
                                                                                        return 18;
                                                                                    case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA /* 49168 */:
                                                                                        return 19;
                                                                                    default:
                                                                                        return -1;
                                                                                }
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                }
        }
    }

    public static Vector getKeyExchangeAlgorithms(int[] iArr) {
        Vector vector = new Vector();
        if (iArr != null) {
            for (int i : iArr) {
                addToSet(vector, getKeyExchangeAlgorithm(i));
            }
            vector.removeElement(Integers.valueOf(-1));
        }
        return vector;
    }

    public static short getLegacyClientCertType(short s) {
        short s2 = 1;
        if (s != 1) {
            s2 = 2;
            if (s != 2) {
                return s != 3 ? (short) -1 : (short) 64;
            }
        }
        return s2;
    }

    public static short getLegacySignatureAlgorithmClient(short s) {
        short s2 = 1;
        if (s != 1) {
            s2 = 2;
            if (s != 2) {
                return s != 64 ? (short) -1 : (short) 3;
            }
        }
        return s2;
    }

    public static short getLegacySignatureAlgorithmClientCert(short s) {
        if (s != 1) {
            if (s != 2) {
                if (s != 3) {
                    if (s != 4) {
                        switch (s) {
                            case 64:
                            case 66:
                                return (short) 3;
                            case 65:
                                break;
                            default:
                                return (short) -1;
                        }
                    }
                }
            }
            return (short) 2;
        }
        return (short) 1;
    }

    public static short getLegacySignatureAlgorithmServer(int i) {
        if (i != 3) {
            if (i != 5) {
                if (i != 17) {
                    if (i != 19) {
                        if (i != 22) {
                            return i != 23 ? (short) -1 : (short) 1;
                        }
                        return (short) 2;
                    }
                    return (short) 1;
                }
                return (short) 3;
            }
            return (short) 1;
        }
        return (short) 2;
    }

    public static short getLegacySignatureAlgorithmServerCert(int i) {
        if (i != 1) {
            if (i == 3) {
                return (short) 2;
            }
            if (i != 5) {
                if (i == 7) {
                    return (short) 2;
                }
                if (i != 9) {
                    if (i == 22) {
                        return (short) 2;
                    }
                    if (i != 23) {
                        switch (i) {
                            case 15:
                            case 18:
                            case 19:
                                break;
                            case 16:
                            case 17:
                                return (short) 3;
                            default:
                                return (short) -1;
                        }
                    }
                }
            }
        }
        return (short) 1;
    }

    public static Vector getLegacySupportedSignatureAlgorithms() {
        Vector vector = new Vector(3);
        vector.add(SignatureAndHashAlgorithm.getInstance((short) 2, (short) 2));
        vector.add(SignatureAndHashAlgorithm.getInstance((short) 2, (short) 3));
        vector.add(SignatureAndHashAlgorithm.getInstance((short) 2, (short) 1));
        return vector;
    }

    public static int getMACAlgorithm(int i) {
        switch (i) {
            case 2:
            case 10:
            case 13:
            case 16:
            case 19:
            case 22:
            case 27:
            case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA /* 147 */:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA /* 148 */:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA /* 149 */:
            case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA /* 150 */:
            case CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA /* 151 */:
            case CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA /* 152 */:
            case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA /* 153 */:
            case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA /* 154 */:
            case CipherSuite.TLS_DH_anon_WITH_SEED_CBC_SHA /* 155 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA /* 49153 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA /* 49170 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA /* 49171 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA /* 49172 */:
            case CipherSuite.TLS_ECDH_anon_WITH_NULL_SHA /* 49173 */:
            case CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA /* 49175 */:
            case CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA /* 49176 */:
            case CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA /* 49177 */:
            case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA /* 49178 */:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA /* 49179 */:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA /* 49180 */:
            case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA /* 49181 */:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA /* 49182 */:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA /* 49183 */:
            case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA /* 49184 */:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA /* 49185 */:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA /* 49186 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA /* 49204 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA /* 49205 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA /* 49206 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA /* 49209 */:
                return 2;
            case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256 /* 156 */:
            case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384 /* 157 */:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 /* 158 */:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 /* 159 */:
            case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256 /* 160 */:
            case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384 /* 161 */:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 /* 162 */:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 /* 163 */:
            case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256 /* 164 */:
            case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384 /* 165 */:
            case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256 /* 166 */:
            case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384 /* 167 */:
            case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256 /* 168 */:
            case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384 /* 169 */:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 /* 170 */:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 /* 171 */:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 /* 172 */:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 /* 173 */:
            case CipherSuite.TLS_SM4_GCM_SM3 /* 198 */:
            case CipherSuite.TLS_SM4_CCM_SM3 /* 199 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 /* 49195 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 /* 49196 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 /* 49197 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 /* 49198 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 /* 49199 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 /* 49200 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 /* 49201 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 /* 49202 */:
            case CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256 /* 49232 */:
            case CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384 /* 49233 */:
            case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 /* 49234 */:
            case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 /* 49235 */:
            case CipherSuite.TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 /* 49236 */:
            case CipherSuite.TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 /* 49237 */:
            case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 /* 49238 */:
            case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 /* 49239 */:
            case CipherSuite.TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 /* 49240 */:
            case CipherSuite.TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 /* 49241 */:
            case CipherSuite.TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 /* 49242 */:
            case CipherSuite.TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 /* 49243 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 /* 49244 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 /* 49245 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 /* 49246 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 /* 49247 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 /* 49248 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 /* 49249 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 /* 49250 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 /* 49251 */:
            case CipherSuite.TLS_PSK_WITH_ARIA_128_GCM_SHA256 /* 49258 */:
            case CipherSuite.TLS_PSK_WITH_ARIA_256_GCM_SHA384 /* 49259 */:
            case CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 /* 49260 */:
            case CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 /* 49261 */:
            case CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 /* 49262 */:
            case CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 /* 49263 */:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 /* 49274 */:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 /* 49275 */:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 /* 49276 */:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 /* 49277 */:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 /* 49278 */:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 /* 49279 */:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 /* 49280 */:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 /* 49281 */:
            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 /* 49282 */:
            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 /* 49283 */:
            case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 /* 49284 */:
            case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 /* 49285 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 /* 49286 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 /* 49287 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 /* 49288 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 /* 49289 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 /* 49290 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 /* 49291 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 /* 49292 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 /* 49293 */:
            case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 /* 49294 */:
            case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 /* 49295 */:
            case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 /* 49296 */:
            case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 /* 49297 */:
            case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 /* 49298 */:
            case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 /* 49299 */:
            case CipherSuite.TLS_RSA_WITH_AES_128_CCM /* 49308 */:
            case CipherSuite.TLS_RSA_WITH_AES_256_CCM /* 49309 */:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM /* 49310 */:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM /* 49311 */:
            case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8 /* 49312 */:
            case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8 /* 49313 */:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8 /* 49314 */:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8 /* 49315 */:
            case CipherSuite.TLS_PSK_WITH_AES_128_CCM /* 49316 */:
            case CipherSuite.TLS_PSK_WITH_AES_256_CCM /* 49317 */:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM /* 49318 */:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM /* 49319 */:
            case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8 /* 49320 */:
            case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8 /* 49321 */:
            case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8 /* 49322 */:
            case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8 /* 49323 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM /* 49324 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM /* 49325 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 /* 49326 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 /* 49327 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 /* 52392 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 /* 52393 */:
            case CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 /* 52394 */:
            case CipherSuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 /* 52395 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 /* 52396 */:
            case CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 /* 52397 */:
            case CipherSuite.TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 /* 52398 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 /* 53249 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 /* 53250 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 /* 53251 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 /* 53253 */:
                return 0;
            case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256 /* 174 */:
            case CipherSuite.TLS_PSK_WITH_NULL_SHA256 /* 176 */:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 /* 178 */:
            case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256 /* 180 */:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 /* 182 */:
            case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA256 /* 184 */:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 /* 186 */:
            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 /* 187 */:
            case 188:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 /* 189 */:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 /* 190 */:
            case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 /* 191 */:
            case 192:
            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 /* 193 */:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 /* 194 */:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 /* 195 */:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 /* 196 */:
            case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 /* 197 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 /* 49187 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 /* 49189 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 /* 49191 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 /* 49193 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 /* 49207 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256 /* 49210 */:
            case CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256 /* 49212 */:
            case CipherSuite.TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 /* 49214 */:
            case CipherSuite.TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 /* 49216 */:
            case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 /* 49218 */:
            case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 /* 49220 */:
            case CipherSuite.TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 /* 49222 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 /* 49224 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 /* 49226 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 /* 49228 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 /* 49230 */:
            case CipherSuite.TLS_PSK_WITH_ARIA_128_CBC_SHA256 /* 49252 */:
            case CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 /* 49254 */:
            case CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 /* 49256 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 /* 49264 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 /* 49266 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 /* 49268 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 /* 49270 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 /* 49272 */:
            case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 /* 49300 */:
            case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 /* 49302 */:
            case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 /* 49304 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 /* 49306 */:
                return 3;
            case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384 /* 175 */:
            case CipherSuite.TLS_PSK_WITH_NULL_SHA384 /* 177 */:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 /* 179 */:
            case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384 /* 181 */:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 /* 183 */:
            case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384 /* 185 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 /* 49188 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 /* 49190 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 /* 49192 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 /* 49194 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 /* 49208 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384 /* 49211 */:
            case CipherSuite.TLS_RSA_WITH_ARIA_256_CBC_SHA384 /* 49213 */:
            case CipherSuite.TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 /* 49215 */:
            case CipherSuite.TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 /* 49217 */:
            case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 /* 49219 */:
            case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 /* 49221 */:
            case CipherSuite.TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 /* 49223 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 /* 49225 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 /* 49227 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 /* 49229 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 /* 49231 */:
            case CipherSuite.TLS_PSK_WITH_ARIA_256_CBC_SHA384 /* 49253 */:
            case CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 /* 49255 */:
            case CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 /* 49257 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 /* 49265 */:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 /* 49267 */:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 /* 49269 */:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 /* 49271 */:
            case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 /* 49273 */:
            case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 /* 49301 */:
            case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 /* 49303 */:
            case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 /* 49305 */:
            case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 /* 49307 */:
                return 4;
            default:
                switch (i) {
                    case 44:
                    case 45:
                    case 46:
                    case 47:
                    case 48:
                    case 49:
                    case 50:
                    case 51:
                    case 52:
                    case 53:
                    case 54:
                    case 55:
                    case 56:
                    case 57:
                    case 58:
                    case 65:
                    case 66:
                    case 67:
                    case 68:
                    case 69:
                    case 70:
                        return 2;
                    case 59:
                    case 60:
                    case 61:
                    case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256 /* 62 */:
                    case 63:
                    case 64:
                        return 3;
                    default:
                        switch (i) {
                            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 /* 103 */:
                            case 104:
                            case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256 /* 105 */:
                            case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 /* 106 */:
                            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 /* 107 */:
                            case 108:
                            case 109:
                                return 3;
                            default:
                                switch (i) {
                                    case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA /* 132 */:
                                    case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA /* 133 */:
                                    case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA /* 134 */:
                                    case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA /* 135 */:
                                    case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA /* 136 */:
                                    case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA /* 137 */:
                                        return 2;
                                    default:
                                        switch (i) {
                                            case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA /* 139 */:
                                            case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA /* 140 */:
                                            case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA /* 141 */:
                                                return 2;
                                            default:
                                                switch (i) {
                                                    case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA /* 143 */:
                                                    case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA /* 144 */:
                                                    case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA /* 145 */:
                                                        return 2;
                                                    default:
                                                        switch (i) {
                                                            case CipherSuite.TLS_AES_128_GCM_SHA256 /* 4865 */:
                                                            case CipherSuite.TLS_AES_256_GCM_SHA384 /* 4866 */:
                                                            case CipherSuite.TLS_CHACHA20_POLY1305_SHA256 /* 4867 */:
                                                            case CipherSuite.TLS_AES_128_CCM_SHA256 /* 4868 */:
                                                            case CipherSuite.TLS_AES_128_CCM_8_SHA256 /* 4869 */:
                                                                return 0;
                                                            default:
                                                                switch (i) {
                                                                    case CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA /* 49155 */:
                                                                    case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA /* 49156 */:
                                                                    case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA /* 49157 */:
                                                                    case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA /* 49158 */:
                                                                        return 2;
                                                                    default:
                                                                        switch (i) {
                                                                            case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA /* 49160 */:
                                                                            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA /* 49161 */:
                                                                            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA /* 49162 */:
                                                                            case CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA /* 49163 */:
                                                                                return 2;
                                                                            default:
                                                                                switch (i) {
                                                                                    case CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA /* 49165 */:
                                                                                    case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA /* 49166 */:
                                                                                    case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA /* 49167 */:
                                                                                    case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA /* 49168 */:
                                                                                        return 2;
                                                                                    default:
                                                                                        return -1;
                                                                                }
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                }
        }
    }

    /*  JADX ERROR: JadxRuntimeException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxRuntimeException: Failed to find switch 'out' block
        	at jadx.core.dex.visitors.regions.RegionMaker.processSwitch(RegionMaker.java:817)
        	at jadx.core.dex.visitors.regions.RegionMaker.traverse(RegionMaker.java:160)
        	at jadx.core.dex.visitors.regions.RegionMaker.makeRegion(RegionMaker.java:94)
        	at jadx.core.dex.visitors.regions.RegionMaker.processSwitch(RegionMaker.java:856)
        	at jadx.core.dex.visitors.regions.RegionMaker.traverse(RegionMaker.java:160)
        	at jadx.core.dex.visitors.regions.RegionMaker.makeRegion(RegionMaker.java:94)
        	at jadx.core.dex.visitors.regions.RegionMaker.processSwitch(RegionMaker.java:856)
        	at jadx.core.dex.visitors.regions.RegionMaker.traverse(RegionMaker.java:160)
        	at jadx.core.dex.visitors.regions.RegionMaker.makeRegion(RegionMaker.java:94)
        	at jadx.core.dex.visitors.regions.RegionMaker.processSwitch(RegionMaker.java:856)
        	at jadx.core.dex.visitors.regions.RegionMaker.traverse(RegionMaker.java:160)
        	at jadx.core.dex.visitors.regions.RegionMaker.makeRegion(RegionMaker.java:94)
        	at jadx.core.dex.visitors.regions.RegionMaker.processSwitch(RegionMaker.java:856)
        	at jadx.core.dex.visitors.regions.RegionMaker.traverse(RegionMaker.java:160)
        	at jadx.core.dex.visitors.regions.RegionMaker.makeRegion(RegionMaker.java:94)
        	at jadx.core.dex.visitors.regions.RegionMakerVisitor.visit(RegionMakerVisitor.java:52)
        */
    public static org.bouncycastle.tls.ProtocolVersion getMinimumVersion(int r0) {
        /*
            switch(r0) {
                case 59: goto L24;
                case 60: goto L24;
                case 61: goto L24;
                case 62: goto L24;
                case 63: goto L24;
                case 64: goto L24;
                default: goto L3;
            }
        L3:
            switch(r0) {
                case 103: goto L24;
                case 104: goto L24;
                case 105: goto L24;
                case 106: goto L24;
                case 107: goto L24;
                case 108: goto L24;
                case 109: goto L24;
                default: goto L6;
            }
        L6:
            switch(r0) {
                case 156: goto L24;
                case 157: goto L24;
                case 158: goto L24;
                case 159: goto L24;
                case 160: goto L24;
                case 161: goto L24;
                case 162: goto L24;
                case 163: goto L24;
                case 164: goto L24;
                case 165: goto L24;
                case 166: goto L24;
                case 167: goto L24;
                case 168: goto L24;
                case 169: goto L24;
                case 170: goto L24;
                case 171: goto L24;
                case 172: goto L24;
                case 173: goto L24;
                default: goto L9;
            }
        L9:
            switch(r0) {
                case 186: goto L24;
                case 187: goto L24;
                case 188: goto L24;
                case 189: goto L24;
                case 190: goto L24;
                case 191: goto L24;
                case 192: goto L24;
                case 193: goto L24;
                case 194: goto L24;
                case 195: goto L24;
                case 196: goto L24;
                case 197: goto L24;
                case 198: goto L21;
                case 199: goto L21;
                default: goto Lc;
            }
        Lc:
            switch(r0) {
                case 4865: goto L21;
                case 4866: goto L21;
                case 4867: goto L21;
                case 4868: goto L21;
                case 4869: goto L21;
                default: goto Lf;
            }
        Lf:
            switch(r0) {
                case 49187: goto L24;
                case 49188: goto L24;
                case 49189: goto L24;
                case 49190: goto L24;
                case 49191: goto L24;
                case 49192: goto L24;
                case 49193: goto L24;
                case 49194: goto L24;
                case 49195: goto L24;
                case 49196: goto L24;
                case 49197: goto L24;
                case 49198: goto L24;
                case 49199: goto L24;
                case 49200: goto L24;
                case 49201: goto L24;
                case 49202: goto L24;
                default: goto L12;
            }
        L12:
            switch(r0) {
                case 49212: goto L24;
                case 49213: goto L24;
                case 49214: goto L24;
                case 49215: goto L24;
                case 49216: goto L24;
                case 49217: goto L24;
                case 49218: goto L24;
                case 49219: goto L24;
                case 49220: goto L24;
                case 49221: goto L24;
                case 49222: goto L24;
                case 49223: goto L24;
                case 49224: goto L24;
                case 49225: goto L24;
                case 49226: goto L24;
                case 49227: goto L24;
                case 49228: goto L24;
                case 49229: goto L24;
                case 49230: goto L24;
                case 49231: goto L24;
                case 49232: goto L24;
                case 49233: goto L24;
                case 49234: goto L24;
                case 49235: goto L24;
                case 49236: goto L24;
                case 49237: goto L24;
                case 49238: goto L24;
                case 49239: goto L24;
                case 49240: goto L24;
                case 49241: goto L24;
                case 49242: goto L24;
                case 49243: goto L24;
                case 49244: goto L24;
                case 49245: goto L24;
                case 49246: goto L24;
                case 49247: goto L24;
                case 49248: goto L24;
                case 49249: goto L24;
                case 49250: goto L24;
                case 49251: goto L24;
                case 49252: goto L24;
                case 49253: goto L24;
                case 49254: goto L24;
                case 49255: goto L24;
                case 49256: goto L24;
                case 49257: goto L24;
                case 49258: goto L24;
                case 49259: goto L24;
                case 49260: goto L24;
                case 49261: goto L24;
                case 49262: goto L24;
                case 49263: goto L24;
                case 49264: goto L24;
                case 49265: goto L24;
                case 49266: goto L24;
                case 49267: goto L24;
                case 49268: goto L24;
                case 49269: goto L24;
                case 49270: goto L24;
                case 49271: goto L24;
                case 49272: goto L24;
                case 49273: goto L24;
                case 49274: goto L24;
                case 49275: goto L24;
                case 49276: goto L24;
                case 49277: goto L24;
                case 49278: goto L24;
                case 49279: goto L24;
                case 49280: goto L24;
                case 49281: goto L24;
                case 49282: goto L24;
                case 49283: goto L24;
                case 49284: goto L24;
                case 49285: goto L24;
                case 49286: goto L24;
                case 49287: goto L24;
                case 49288: goto L24;
                case 49289: goto L24;
                case 49290: goto L24;
                case 49291: goto L24;
                case 49292: goto L24;
                case 49293: goto L24;
                case 49294: goto L24;
                case 49295: goto L24;
                case 49296: goto L24;
                case 49297: goto L24;
                case 49298: goto L24;
                case 49299: goto L24;
                case 53249: goto L24;
                case 53250: goto L24;
                case 53251: goto L24;
                case 53253: goto L24;
                default: goto L15;
            }
        L15:
            switch(r0) {
                case 49308: goto L24;
                case 49309: goto L24;
                case 49310: goto L24;
                case 49311: goto L24;
                case 49312: goto L24;
                case 49313: goto L24;
                case 49314: goto L24;
                case 49315: goto L24;
                case 49316: goto L24;
                case 49317: goto L24;
                case 49318: goto L24;
                case 49319: goto L24;
                case 49320: goto L24;
                case 49321: goto L24;
                case 49322: goto L24;
                case 49323: goto L24;
                case 49324: goto L24;
                case 49325: goto L24;
                case 49326: goto L24;
                case 49327: goto L24;
                default: goto L18;
            }
        L18:
            switch(r0) {
                case 49408: goto L24;
                case 49409: goto L24;
                case 49410: goto L24;
                default: goto L1b;
            }
        L1b:
            switch(r0) {
                case 52392: goto L24;
                case 52393: goto L24;
                case 52394: goto L24;
                case 52395: goto L24;
                case 52396: goto L24;
                case 52397: goto L24;
                case 52398: goto L24;
                default: goto L1e;
            }
        L1e:
            org.bouncycastle.tls.ProtocolVersion r0 = org.bouncycastle.tls.ProtocolVersion.SSLv3
            return r0
        L21:
            org.bouncycastle.tls.ProtocolVersion r0 = org.bouncycastle.tls.ProtocolVersion.TLSv13
            return r0
        L24:
            org.bouncycastle.tls.ProtocolVersion r0 = org.bouncycastle.tls.ProtocolVersion.TLSv12
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.TlsUtils.getMinimumVersion(int):org.bouncycastle.tls.ProtocolVersion");
    }

    public static Vector getNamedGroupRoles(Vector vector) {
        Vector vector2 = new Vector();
        for (int i = 0; i < vector.size(); i++) {
            int intValue = ((Integer) vector.elementAt(i)).intValue();
            if (intValue == 0) {
                addToSet(vector2, 1);
                addToSet(vector2, 2);
                addToSet(vector2, 4);
            } else if (intValue == 3 || intValue == 5 || intValue == 7 || intValue == 9 || intValue == 11 || intValue == 14) {
                addToSet(vector2, 1);
            } else {
                if (intValue != 24) {
                    switch (intValue) {
                        case 16:
                        case 17:
                            addToSet(vector2, 2);
                            addToSet(vector2, 3);
                            break;
                    }
                }
                addToSet(vector2, 2);
            }
        }
        return vector2;
    }

    public static Vector getNamedGroupRoles(int[] iArr) {
        return getNamedGroupRoles(getKeyExchangeAlgorithms(iArr));
    }

    public static ASN1ObjectIdentifier getOIDForHashAlgorithm(short s) {
        switch (s) {
            case 1:
                return PKCSObjectIdentifiers.md5;
            case 2:
                return X509ObjectIdentifiers.id_SHA1;
            case 3:
                return NISTObjectIdentifiers.id_sha224;
            case 4:
                return NISTObjectIdentifiers.id_sha256;
            case 5:
                return NISTObjectIdentifiers.id_sha384;
            case 6:
                return NISTObjectIdentifiers.id_sha512;
            default:
                throw new IllegalArgumentException("invalid HashAlgorithm: " + HashAlgorithm.getText(s));
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:48:0x0073  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0082  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    static int getPRFAlgorithm(org.bouncycastle.tls.SecurityParameters r7, int r8) throws java.io.IOException {
        /*
            org.bouncycastle.tls.ProtocolVersion r7 = r7.getNegotiatedVersion()
            boolean r0 = isTLSv13(r7)
            r1 = 1
            r2 = 0
            if (r0 != 0) goto L14
            boolean r3 = isTLSv12(r7)
            if (r3 == 0) goto L14
            r3 = r1
            goto L15
        L14:
            r3 = r2
        L15:
            boolean r7 = r7.isSSL()
            r4 = 2
            r5 = 47
            switch(r8) {
                case 59: goto L8b;
                case 60: goto L8b;
                case 61: goto L8b;
                case 62: goto L8b;
                case 63: goto L8b;
                case 64: goto L8b;
                default: goto L1f;
            }
        L1f:
            switch(r8) {
                case 103: goto L8b;
                case 104: goto L8b;
                case 105: goto L8b;
                case 106: goto L8b;
                case 107: goto L8b;
                case 108: goto L8b;
                case 109: goto L8b;
                default: goto L22;
            }
        L22:
            r6 = 3
            switch(r8) {
                case 156: goto L8b;
                case 157: goto L82;
                case 158: goto L8b;
                case 159: goto L82;
                case 160: goto L8b;
                case 161: goto L82;
                case 162: goto L8b;
                case 163: goto L82;
                case 164: goto L8b;
                case 165: goto L82;
                case 166: goto L8b;
                case 167: goto L82;
                case 168: goto L8b;
                case 169: goto L82;
                case 170: goto L8b;
                case 171: goto L82;
                case 172: goto L8b;
                case 173: goto L82;
                default: goto L26;
            }
        L26:
            switch(r8) {
                case 175: goto L73;
                case 177: goto L73;
                case 179: goto L73;
                case 181: goto L73;
                case 183: goto L73;
                case 49208: goto L73;
                case 49211: goto L73;
                case 49212: goto L8b;
                case 49213: goto L82;
                case 49214: goto L8b;
                case 49215: goto L82;
                case 49216: goto L8b;
                case 49217: goto L82;
                case 49218: goto L8b;
                case 49219: goto L82;
                case 49220: goto L8b;
                case 49221: goto L82;
                case 49222: goto L8b;
                case 49223: goto L82;
                case 49224: goto L8b;
                case 49225: goto L82;
                case 49226: goto L8b;
                case 49227: goto L82;
                case 49228: goto L8b;
                case 49229: goto L82;
                case 49230: goto L8b;
                case 49231: goto L82;
                case 49232: goto L8b;
                case 49233: goto L82;
                case 49234: goto L8b;
                case 49235: goto L82;
                case 49236: goto L8b;
                case 49237: goto L82;
                case 49238: goto L8b;
                case 49239: goto L82;
                case 49240: goto L8b;
                case 49241: goto L82;
                case 49242: goto L8b;
                case 49243: goto L82;
                case 49244: goto L8b;
                case 49245: goto L82;
                case 49246: goto L8b;
                case 49247: goto L82;
                case 49248: goto L8b;
                case 49249: goto L82;
                case 49250: goto L8b;
                case 49251: goto L82;
                case 49252: goto L8b;
                case 49253: goto L82;
                case 49254: goto L8b;
                case 49255: goto L82;
                case 49256: goto L8b;
                case 49257: goto L82;
                case 49258: goto L8b;
                case 49259: goto L82;
                case 49260: goto L8b;
                case 49261: goto L82;
                case 49262: goto L8b;
                case 49263: goto L82;
                case 49264: goto L8b;
                case 49265: goto L82;
                case 49266: goto L8b;
                case 49267: goto L82;
                case 49268: goto L8b;
                case 49269: goto L82;
                case 49270: goto L8b;
                case 49271: goto L82;
                case 49272: goto L8b;
                case 49273: goto L82;
                case 49274: goto L8b;
                case 49275: goto L82;
                case 49276: goto L8b;
                case 49277: goto L82;
                case 49278: goto L8b;
                case 49279: goto L82;
                case 49280: goto L8b;
                case 49281: goto L82;
                case 49282: goto L8b;
                case 49283: goto L82;
                case 49284: goto L8b;
                case 49285: goto L82;
                case 49286: goto L8b;
                case 49287: goto L82;
                case 49288: goto L8b;
                case 49289: goto L82;
                case 49290: goto L8b;
                case 49291: goto L82;
                case 49292: goto L8b;
                case 49293: goto L82;
                case 49294: goto L8b;
                case 49295: goto L82;
                case 49296: goto L8b;
                case 49297: goto L82;
                case 49298: goto L8b;
                case 49299: goto L82;
                case 49301: goto L73;
                case 49303: goto L73;
                case 49305: goto L73;
                case 53249: goto L8b;
                case 53250: goto L82;
                case 53251: goto L8b;
                case 53253: goto L8b;
                default: goto L29;
            }
        L29:
            switch(r8) {
                case 185: goto L73;
                case 186: goto L8b;
                case 187: goto L8b;
                case 188: goto L8b;
                case 189: goto L8b;
                case 190: goto L8b;
                case 191: goto L8b;
                case 192: goto L8b;
                case 193: goto L8b;
                case 194: goto L8b;
                case 195: goto L8b;
                case 196: goto L8b;
                case 197: goto L8b;
                case 198: goto L69;
                case 199: goto L69;
                default: goto L2c;
            }
        L2c:
            switch(r8) {
                case 4865: goto L5f;
                case 4866: goto L55;
                case 4867: goto L5f;
                case 4868: goto L5f;
                case 4869: goto L5f;
                default: goto L2f;
            }
        L2f:
            switch(r8) {
                case 49187: goto L8b;
                case 49188: goto L82;
                case 49189: goto L8b;
                case 49190: goto L82;
                case 49191: goto L8b;
                case 49192: goto L82;
                case 49193: goto L8b;
                case 49194: goto L82;
                case 49195: goto L8b;
                case 49196: goto L82;
                case 49197: goto L8b;
                case 49198: goto L82;
                case 49199: goto L8b;
                case 49200: goto L82;
                case 49201: goto L8b;
                case 49202: goto L82;
                default: goto L32;
            }
        L32:
            switch(r8) {
                case 49307: goto L73;
                case 49308: goto L8b;
                case 49309: goto L8b;
                case 49310: goto L8b;
                case 49311: goto L8b;
                case 49312: goto L8b;
                case 49313: goto L8b;
                case 49314: goto L8b;
                case 49315: goto L8b;
                case 49316: goto L8b;
                case 49317: goto L8b;
                case 49318: goto L8b;
                case 49319: goto L8b;
                case 49320: goto L8b;
                case 49321: goto L8b;
                case 49322: goto L8b;
                case 49323: goto L8b;
                case 49324: goto L8b;
                case 49325: goto L8b;
                case 49326: goto L8b;
                case 49327: goto L8b;
                default: goto L35;
            }
        L35:
            switch(r8) {
                case 49408: goto L4a;
                case 49409: goto L4a;
                case 49410: goto L4a;
                default: goto L38;
            }
        L38:
            switch(r8) {
                case 52392: goto L8b;
                case 52393: goto L8b;
                case 52394: goto L8b;
                case 52395: goto L8b;
                case 52396: goto L8b;
                case 52397: goto L8b;
                case 52398: goto L8b;
                default: goto L3b;
            }
        L3b:
            if (r0 != 0) goto L44
            if (r3 == 0) goto L40
            return r4
        L40:
            if (r7 == 0) goto L43
            return r2
        L43:
            return r1
        L44:
            org.bouncycastle.tls.TlsFatalAlert r7 = new org.bouncycastle.tls.TlsFatalAlert
            r7.<init>(r5)
            throw r7
        L4a:
            if (r3 == 0) goto L4f
            r7 = 8
            return r7
        L4f:
            org.bouncycastle.tls.TlsFatalAlert r7 = new org.bouncycastle.tls.TlsFatalAlert
            r7.<init>(r5)
            throw r7
        L55:
            if (r0 == 0) goto L59
            r7 = 5
            return r7
        L59:
            org.bouncycastle.tls.TlsFatalAlert r7 = new org.bouncycastle.tls.TlsFatalAlert
            r7.<init>(r5)
            throw r7
        L5f:
            if (r0 == 0) goto L63
            r7 = 4
            return r7
        L63:
            org.bouncycastle.tls.TlsFatalAlert r7 = new org.bouncycastle.tls.TlsFatalAlert
            r7.<init>(r5)
            throw r7
        L69:
            if (r0 == 0) goto L6d
            r7 = 7
            return r7
        L6d:
            org.bouncycastle.tls.TlsFatalAlert r7 = new org.bouncycastle.tls.TlsFatalAlert
            r7.<init>(r5)
            throw r7
        L73:
            if (r0 != 0) goto L7c
            if (r3 == 0) goto L78
            return r6
        L78:
            if (r7 == 0) goto L7b
            return r2
        L7b:
            return r1
        L7c:
            org.bouncycastle.tls.TlsFatalAlert r7 = new org.bouncycastle.tls.TlsFatalAlert
            r7.<init>(r5)
            throw r7
        L82:
            if (r3 == 0) goto L85
            return r6
        L85:
            org.bouncycastle.tls.TlsFatalAlert r7 = new org.bouncycastle.tls.TlsFatalAlert
            r7.<init>(r5)
            throw r7
        L8b:
            if (r3 == 0) goto L8e
            return r4
        L8e:
            org.bouncycastle.tls.TlsFatalAlert r7 = new org.bouncycastle.tls.TlsFatalAlert
            r7.<init>(r5)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.TlsUtils.getPRFAlgorithm(org.bouncycastle.tls.SecurityParameters, int):int");
    }

    static int getPRFAlgorithm13(int i) {
        if (i == 198 || i == 199) {
            return 7;
        }
        switch (i) {
            case CipherSuite.TLS_AES_128_GCM_SHA256 /* 4865 */:
            case CipherSuite.TLS_CHACHA20_POLY1305_SHA256 /* 4867 */:
            case CipherSuite.TLS_AES_128_CCM_SHA256 /* 4868 */:
            case CipherSuite.TLS_AES_128_CCM_8_SHA256 /* 4869 */:
                return 4;
            case CipherSuite.TLS_AES_256_GCM_SHA384 /* 4866 */:
                return 5;
            default:
                return -1;
        }
    }

    static int[] getPRFAlgorithms13(int[] iArr) {
        int[] iArr2 = new int[Math.min(3, iArr.length)];
        int i = 0;
        for (int i2 : iArr) {
            int pRFAlgorithm13 = getPRFAlgorithm13(i2);
            if (pRFAlgorithm13 >= 0 && !Arrays.contains(iArr2, pRFAlgorithm13)) {
                iArr2[i] = pRFAlgorithm13;
                i++;
            }
        }
        return truncate(iArr2, i);
    }

    static TlsSecret getPSKEarlySecret(TlsCrypto tlsCrypto, TlsPSK tlsPSK) {
        int hashForPRF = TlsCryptoUtils.getHashForPRF(tlsPSK.getPRFAlgorithm());
        return tlsCrypto.hkdfInit(hashForPRF).hkdfExtract(hashForPRF, tlsPSK.getKey());
    }

    static TlsSecret[] getPSKEarlySecrets(TlsCrypto tlsCrypto, TlsPSK[] tlsPSKArr) {
        int length = tlsPSKArr.length;
        TlsSecret[] tlsSecretArr = new TlsSecret[length];
        for (int i = 0; i < length; i++) {
            tlsSecretArr[i] = getPSKEarlySecret(tlsCrypto, tlsPSKArr[i]);
        }
        return tlsSecretArr;
    }

    static TlsPSKExternal[] getPSKExternalsClient(TlsClient tlsClient, int[] iArr) throws IOException {
        Vector externalPSKs = tlsClient.getExternalPSKs();
        if (isNullOrEmpty(externalPSKs)) {
            return null;
        }
        int[] pRFAlgorithms13 = getPRFAlgorithms13(iArr);
        int size = externalPSKs.size();
        TlsPSKExternal[] tlsPSKExternalArr = new TlsPSKExternal[size];
        for (int i = 0; i < size; i++) {
            Object elementAt = externalPSKs.elementAt(i);
            if (!(elementAt instanceof TlsPSKExternal)) {
                throw new TlsFatalAlert((short) 80, "External PSKs element is not a TlsPSKExternal");
            }
            TlsPSKExternal tlsPSKExternal = (TlsPSKExternal) elementAt;
            if (!Arrays.contains(pRFAlgorithms13, tlsPSKExternal.getPRFAlgorithm())) {
                throw new TlsFatalAlert((short) 80, "External PSK incompatible with offered cipher suites");
            }
            tlsPSKExternalArr[i] = tlsPSKExternal;
        }
        return tlsPSKExternalArr;
    }

    static Vector getPSKIndices(TlsPSK[] tlsPSKArr, int i) {
        Vector vector = new Vector(tlsPSKArr.length);
        for (int i2 = 0; i2 < tlsPSKArr.length; i2++) {
            if (tlsPSKArr[i2].getPRFAlgorithm() == i) {
                vector.add(Integers.valueOf(i2));
            }
        }
        return vector;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] getSessionID(TlsSession tlsSession) {
        byte[] sessionID;
        return (tlsSession == null || (sessionID = tlsSession.getSessionID()) == null || sessionID.length <= 0 || sessionID.length > 32) ? EMPTY_BYTES : sessionID;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TlsSecret getSessionMasterSecret(TlsCrypto tlsCrypto, TlsSecret tlsSecret) {
        if (tlsSecret != null) {
            synchronized (tlsSecret) {
                if (tlsSecret.isAlive()) {
                    return tlsCrypto.adoptSecret(tlsSecret);
                }
                return null;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(ProtocolVersion protocolVersion, TlsCredentialedSigner tlsCredentialedSigner) throws IOException {
        if (isSignatureAlgorithmsExtensionAllowed(protocolVersion)) {
            SignatureAndHashAlgorithm signatureAndHashAlgorithm = tlsCredentialedSigner.getSignatureAndHashAlgorithm();
            if (signatureAndHashAlgorithm != null) {
                return signatureAndHashAlgorithm;
            }
            throw new TlsFatalAlert((short) 80);
        }
        return null;
    }

    public static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(TlsContext tlsContext, TlsCredentialedSigner tlsCredentialedSigner) throws IOException {
        return getSignatureAndHashAlgorithm(tlsContext.getServerVersion(), tlsCredentialedSigner);
    }

    public static int[] getSupportedCipherSuites(TlsCrypto tlsCrypto, int[] iArr) {
        return getSupportedCipherSuites(tlsCrypto, iArr, 0, iArr.length);
    }

    public static int[] getSupportedCipherSuites(TlsCrypto tlsCrypto, int[] iArr, int i) {
        return getSupportedCipherSuites(tlsCrypto, iArr, 0, i);
    }

    public static int[] getSupportedCipherSuites(TlsCrypto tlsCrypto, int[] iArr, int i, int i2) {
        int[] iArr2 = new int[i2];
        int i3 = 0;
        for (int i4 = 0; i4 < i2; i4++) {
            int i5 = iArr[i + i4];
            if (isSupportedCipherSuite(tlsCrypto, i5)) {
                iArr2[i3] = i5;
                i3++;
            }
        }
        return i3 < i2 ? Arrays.copyOf(iArr2, i3) : iArr2;
    }

    public static Vector getSupportedSignatureAlgorithms(TlsContext tlsContext, Vector vector) {
        TlsCrypto crypto = tlsContext.getCrypto();
        int size = vector.size();
        Vector vector2 = new Vector(size);
        for (int i = 0; i < size; i++) {
            addIfSupported(vector2, crypto, (SignatureAndHashAlgorithm) vector.elementAt(i));
        }
        return vector2;
    }

    public static Vector getUsableSignatureAlgorithms(Vector vector) {
        if (vector == null) {
            Vector vector2 = new Vector(3);
            vector2.addElement(Shorts.valueOf((short) 1));
            vector2.addElement(Shorts.valueOf((short) 2));
            vector2.addElement(Shorts.valueOf((short) 3));
            return vector2;
        }
        Vector vector3 = new Vector();
        for (int i = 0; i < vector.size(); i++) {
            SignatureAndHashAlgorithm signatureAndHashAlgorithm = (SignatureAndHashAlgorithm) vector.elementAt(i);
            if (signatureAndHashAlgorithm.getHash() >= 2) {
                Short valueOf = Shorts.valueOf(signatureAndHashAlgorithm.getSignature());
                if (!vector3.contains(valueOf)) {
                    vector3.addElement(valueOf);
                }
            }
        }
        return vector3;
    }

    static boolean hasAnyRSASigAlgs(TlsCrypto tlsCrypto) {
        return tlsCrypto.hasSignatureAlgorithm((short) 1) || tlsCrypto.hasSignatureAlgorithm((short) 4) || tlsCrypto.hasSignatureAlgorithm((short) 5) || tlsCrypto.hasSignatureAlgorithm((short) 6) || tlsCrypto.hasSignatureAlgorithm((short) 9) || tlsCrypto.hasSignatureAlgorithm((short) 10) || tlsCrypto.hasSignatureAlgorithm((short) 11);
    }

    public static boolean hasExpectedEmptyExtensionData(Hashtable hashtable, Integer num, short s) throws IOException {
        byte[] extensionData = getExtensionData(hashtable, num);
        if (extensionData == null) {
            return false;
        }
        if (extensionData.length == 0) {
            return true;
        }
        throw new TlsFatalAlert(s);
    }

    public static boolean hasSigningCapability(short s) {
        return s == 1 || s == 2 || s == 64;
    }

    public static TlsSession importSession(byte[] bArr, SessionParameters sessionParameters) {
        return new TlsSessionImpl(bArr, sessionParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TlsCipher initCipher(TlsContext tlsContext) throws IOException {
        int cipherSuite = tlsContext.getSecurityParametersHandshake().getCipherSuite();
        int encryptionAlgorithm = getEncryptionAlgorithm(cipherSuite);
        int mACAlgorithm = getMACAlgorithm(cipherSuite);
        if (encryptionAlgorithm < 0 || mACAlgorithm < 0) {
            throw new TlsFatalAlert((short) 80);
        }
        return tlsContext.getCrypto().createCipher(new TlsCryptoParameters(tlsContext), encryptionAlgorithm, mACAlgorithm);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TlsKeyExchange initKeyExchangeClient(TlsClientContext tlsClientContext, TlsClient tlsClient) throws IOException {
        TlsKeyExchange createKeyExchangeClient = createKeyExchangeClient(tlsClient, tlsClientContext.getSecurityParametersHandshake().getKeyExchangeAlgorithm());
        createKeyExchangeClient.init(tlsClientContext);
        return createKeyExchangeClient;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TlsKeyExchange initKeyExchangeServer(TlsServerContext tlsServerContext, TlsServer tlsServer) throws IOException {
        TlsKeyExchange createKeyExchangeServer = createKeyExchangeServer(tlsServer, tlsServerContext.getSecurityParametersHandshake().getKeyExchangeAlgorithm());
        createKeyExchangeServer.init(tlsServerContext);
        return createKeyExchangeServer;
    }

    public static boolean isAEADCipherSuite(int i) throws IOException {
        return 2 == getCipherType(i);
    }

    public static boolean isBlockCipherSuite(int i) throws IOException {
        return 1 == getCipherType(i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isExtendedMasterSecretOptional(ProtocolVersion protocolVersion) {
        ProtocolVersion equivalentTLSVersion = protocolVersion.getEquivalentTLSVersion();
        return ProtocolVersion.TLSv12.equals(equivalentTLSVersion) || ProtocolVersion.TLSv11.equals(equivalentTLSVersion) || ProtocolVersion.TLSv10.equals(equivalentTLSVersion);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isExtendedMasterSecretOptional(ProtocolVersion[] protocolVersionArr) {
        if (protocolVersionArr != null) {
            for (ProtocolVersion protocolVersion : protocolVersionArr) {
                if (isExtendedMasterSecretOptional(protocolVersion)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean isNullOrContainsNull(Object[] objArr) {
        if (objArr == null) {
            return true;
        }
        for (Object obj : objArr) {
            if (obj == null) {
                return true;
            }
        }
        return false;
    }

    public static boolean isNullOrEmpty(String str) {
        return str == null || str.length() < 1;
    }

    public static boolean isNullOrEmpty(Vector vector) {
        return vector == null || vector.isEmpty();
    }

    public static boolean isNullOrEmpty(byte[] bArr) {
        return bArr == null || bArr.length < 1;
    }

    public static boolean isNullOrEmpty(int[] iArr) {
        return iArr == null || iArr.length < 1;
    }

    public static boolean isNullOrEmpty(Object[] objArr) {
        return objArr == null || objArr.length < 1;
    }

    public static boolean isNullOrEmpty(short[] sArr) {
        return sArr == null || sArr.length < 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0033  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x004a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static boolean isPermittedExtensionType13(int r6, int r7) {
        /*
            r0 = 8
            r1 = 0
            r2 = 1
            if (r7 == 0) goto L5e
            if (r7 == r2) goto L5e
            r3 = 5
            r4 = 13
            if (r7 == r3) goto L54
            r3 = 10
            if (r7 == r3) goto L5e
            r3 = 27
            if (r7 == r3) goto L4e
            switch(r7) {
                case 13: goto L4e;
                case 14: goto L5e;
                case 15: goto L5e;
                case 16: goto L5e;
                default: goto L18;
            }
        L18:
            switch(r7) {
                case 18: goto L54;
                case 19: goto L5e;
                case 20: goto L5e;
                case 21: goto L4a;
                default: goto L1b;
            }
        L1b:
            r3 = 6
            r5 = 2
            switch(r7) {
                case 41: goto L44;
                case 42: goto L3b;
                case 43: goto L33;
                case 44: goto L2d;
                case 45: goto L4a;
                default: goto L20;
            }
        L20:
            switch(r7) {
                case 47: goto L4e;
                case 48: goto L29;
                case 49: goto L4a;
                case 50: goto L4e;
                case 51: goto L33;
                default: goto L23;
            }
        L23:
            boolean r6 = org.bouncycastle.tls.ExtensionType.isRecognized(r7)
            r6 = r6 ^ r2
            return r6
        L29:
            if (r6 == r4) goto L2c
            return r1
        L2c:
            return r2
        L2d:
            if (r6 == r2) goto L32
            if (r6 == r3) goto L32
            return r1
        L32:
            return r2
        L33:
            if (r6 == r2) goto L3a
            if (r6 == r5) goto L3a
            if (r6 == r3) goto L3a
            return r1
        L3a:
            return r2
        L3b:
            if (r6 == r2) goto L43
            r7 = 4
            if (r6 == r7) goto L43
            if (r6 == r0) goto L43
            return r1
        L43:
            return r2
        L44:
            if (r6 == r2) goto L49
            if (r6 == r5) goto L49
            return r1
        L49:
            return r2
        L4a:
            if (r6 == r2) goto L4d
            return r1
        L4d:
            return r2
        L4e:
            if (r6 == r2) goto L53
            if (r6 == r4) goto L53
            return r1
        L53:
            return r2
        L54:
            if (r6 == r2) goto L5d
            r7 = 11
            if (r6 == r7) goto L5d
            if (r6 == r4) goto L5d
            return r1
        L5d:
            return r2
        L5e:
            if (r6 == r2) goto L63
            if (r6 == r0) goto L63
            return r1
        L63:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.TlsUtils.isPermittedExtensionType13(int, int):boolean");
    }

    public static boolean isSSL(TlsContext tlsContext) {
        return tlsContext.getServerVersion().isSSL();
    }

    private static boolean isSafeRenegotiationServerCertificate(TlsClientContext tlsClientContext, Certificate certificate) {
        Certificate peerCertificate;
        SecurityParameters securityParametersConnection = tlsClientContext.getSecurityParametersConnection();
        if (securityParametersConnection == null || (peerCertificate = securityParametersConnection.getPeerCertificate()) == null) {
            return false;
        }
        return areCertificatesEqual(peerCertificate, certificate);
    }

    public static boolean isSignatureAlgorithmsExtensionAllowed(ProtocolVersion protocolVersion) {
        return protocolVersion != null && ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(protocolVersion.getEquivalentTLSVersion());
    }

    public static boolean isStreamCipherSuite(int i) throws IOException {
        return getCipherType(i) == 0;
    }

    public static boolean isSupportedCipherSuite(TlsCrypto tlsCrypto, int i) {
        int encryptionAlgorithm;
        if (isSupportedKeyExchange(tlsCrypto, getKeyExchangeAlgorithm(i)) && (encryptionAlgorithm = getEncryptionAlgorithm(i)) >= 0 && tlsCrypto.hasEncryptionAlgorithm(encryptionAlgorithm)) {
            int mACAlgorithm = getMACAlgorithm(i);
            if (mACAlgorithm != 0) {
                return mACAlgorithm >= 0 && tlsCrypto.hasMacAlgorithm(mACAlgorithm);
            }
            return true;
        }
        return false;
    }

    public static boolean isSupportedKeyExchange(TlsCrypto tlsCrypto, int i) {
        if (i != 0) {
            if (i != 1) {
                if (i == 3) {
                    return tlsCrypto.hasDHAgreement() && tlsCrypto.hasSignatureAlgorithm((short) 2);
                } else if (i == 5) {
                    return tlsCrypto.hasDHAgreement() && hasAnyRSASigAlgs(tlsCrypto);
                } else {
                    if (i != 7 && i != 9 && i != 11) {
                        switch (i) {
                            case 13:
                                break;
                            case 14:
                                break;
                            case 15:
                                break;
                            case 16:
                            case 18:
                            case 20:
                            case 24:
                                return tlsCrypto.hasECDHAgreement();
                            case 17:
                                return tlsCrypto.hasECDHAgreement() && (tlsCrypto.hasSignatureAlgorithm((short) 3) || tlsCrypto.hasSignatureAlgorithm((short) 7) || tlsCrypto.hasSignatureAlgorithm((short) 8));
                            case 19:
                                return tlsCrypto.hasECDHAgreement() && hasAnyRSASigAlgs(tlsCrypto);
                            case 21:
                                return tlsCrypto.hasSRPAuthentication();
                            case 22:
                                return tlsCrypto.hasSRPAuthentication() && tlsCrypto.hasSignatureAlgorithm((short) 2);
                            case 23:
                                return tlsCrypto.hasSRPAuthentication() && hasAnyRSASigAlgs(tlsCrypto);
                            default:
                                return false;
                        }
                    }
                    return tlsCrypto.hasDHAgreement();
                }
            }
            return tlsCrypto.hasRSAEncryption();
        }
        return true;
    }

    public static boolean isTLSv10(ProtocolVersion protocolVersion) {
        return ProtocolVersion.TLSv10.isEqualOrEarlierVersionOf(protocolVersion.getEquivalentTLSVersion());
    }

    public static boolean isTLSv10(TlsContext tlsContext) {
        return isTLSv10(tlsContext.getServerVersion());
    }

    public static boolean isTLSv11(ProtocolVersion protocolVersion) {
        return ProtocolVersion.TLSv11.isEqualOrEarlierVersionOf(protocolVersion.getEquivalentTLSVersion());
    }

    public static boolean isTLSv11(TlsContext tlsContext) {
        return isTLSv11(tlsContext.getServerVersion());
    }

    public static boolean isTLSv12(ProtocolVersion protocolVersion) {
        return ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(protocolVersion.getEquivalentTLSVersion());
    }

    public static boolean isTLSv12(TlsContext tlsContext) {
        return isTLSv12(tlsContext.getServerVersion());
    }

    public static boolean isTLSv13(ProtocolVersion protocolVersion) {
        return ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(protocolVersion.getEquivalentTLSVersion());
    }

    public static boolean isTLSv13(TlsContext tlsContext) {
        return isTLSv13(tlsContext.getServerVersion());
    }

    public static boolean isValidCipherSuiteForSignatureAlgorithms(int i, Vector vector) {
        int keyExchangeAlgorithm = getKeyExchangeAlgorithm(i);
        if (keyExchangeAlgorithm == 0 || keyExchangeAlgorithm == 3 || keyExchangeAlgorithm == 5 || keyExchangeAlgorithm == 17 || keyExchangeAlgorithm == 19 || keyExchangeAlgorithm == 22 || keyExchangeAlgorithm == 23) {
            int size = vector.size();
            for (int i2 = 0; i2 < size; i2++) {
                Short sh = (Short) vector.elementAt(i2);
                if (sh != null && isValidSignatureAlgorithmForServerKeyExchange(sh.shortValue(), keyExchangeAlgorithm)) {
                    return true;
                }
            }
            return false;
        }
        return true;
    }

    public static boolean isValidCipherSuiteForVersion(int i, ProtocolVersion protocolVersion) {
        return isValidVersionForCipherSuite(i, protocolVersion);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isValidCipherSuiteSelection(int[] iArr, int i) {
        return (iArr == null || !Arrays.contains(iArr, i) || i == 0 || CipherSuite.isSCSV(i)) ? false : true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isValidKeyShareSelection(ProtocolVersion protocolVersion, int[] iArr, Hashtable hashtable, int i) {
        return iArr != null && Arrays.contains(iArr, i) && !hashtable.containsKey(Integers.valueOf(i)) && NamedGroup.canBeNegotiated(i, protocolVersion);
    }

    static boolean isValidSignatureAlgorithmForServerKeyExchange(short s, int i) {
        if (i == 0) {
            return s != 0;
        }
        if (i != 3) {
            if (i != 5) {
                if (i == 17) {
                    return s == 3 || s == 7 || s == 8;
                } else if (i != 19) {
                    if (i != 22) {
                        if (i != 23) {
                            return false;
                        }
                    }
                }
            }
            if (s != 1 && s != 4 && s != 5 && s != 6) {
                switch (s) {
                    case 9:
                    case 10:
                    case 11:
                        break;
                    default:
                        return false;
                }
            }
            return true;
        }
        return 2 == s;
    }

    public static boolean isValidSignatureSchemeForServerKeyExchange(int i, int i2) {
        return isValidSignatureAlgorithmForServerKeyExchange(SignatureScheme.getSignatureAlgorithm(i), i2);
    }

    public static boolean isValidUint16(int i) {
        return (65535 & i) == i;
    }

    public static boolean isValidUint16(long j) {
        return (65535 & j) == j;
    }

    public static boolean isValidUint24(int i) {
        return (16777215 & i) == i;
    }

    public static boolean isValidUint24(long j) {
        return (16777215 & j) == j;
    }

    public static boolean isValidUint32(long j) {
        return (BodyPartID.bodyIdMax & j) == j;
    }

    public static boolean isValidUint48(long j) {
        return (281474976710655L & j) == j;
    }

    public static boolean isValidUint64(long j) {
        return true;
    }

    public static boolean isValidUint8(int i) {
        return (i & 255) == i;
    }

    public static boolean isValidUint8(long j) {
        return (255 & j) == j;
    }

    public static boolean isValidUint8(short s) {
        return (s & 255) == s;
    }

    public static boolean isValidVersionForCipherSuite(int i, ProtocolVersion protocolVersion) {
        ProtocolVersion equivalentTLSVersion = protocolVersion.getEquivalentTLSVersion();
        ProtocolVersion minimumVersion = getMinimumVersion(i);
        if (minimumVersion == equivalentTLSVersion) {
            return true;
        }
        if (minimumVersion.isEarlierVersionOf(equivalentTLSVersion)) {
            return ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(minimumVersion) || ProtocolVersion.TLSv13.isLaterVersionOf(equivalentTLSVersion);
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void negotiatedCipherSuite(SecurityParameters securityParameters, int i) throws IOException {
        int i2;
        int i3;
        securityParameters.cipherSuite = i;
        securityParameters.keyExchangeAlgorithm = getKeyExchangeAlgorithm(i);
        int pRFAlgorithm = getPRFAlgorithm(securityParameters, i);
        securityParameters.prfAlgorithm = pRFAlgorithm;
        if (pRFAlgorithm == 0 || pRFAlgorithm == 1) {
            i2 = -1;
            securityParameters.prfCryptoHashAlgorithm = -1;
        } else {
            int hashForPRF = TlsCryptoUtils.getHashForPRF(pRFAlgorithm);
            securityParameters.prfCryptoHashAlgorithm = hashForPRF;
            i2 = TlsCryptoUtils.getHashOutputSize(hashForPRF);
        }
        securityParameters.prfHashLength = i2;
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
        if (!isTLSv13(negotiatedVersion)) {
            if (!negotiatedVersion.isSSL()) {
                switch (i) {
                    case CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC /* 49408 */:
                    case CipherSuite.TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC /* 49409 */:
                        i3 = 32;
                        break;
                    default:
                        i3 = 12;
                        break;
                }
            } else {
                i3 = 36;
            }
        } else {
            i3 = securityParameters.getPRFHashLength();
        }
        securityParameters.verifyDataLength = i3;
    }

    static void negotiatedVersion(SecurityParameters securityParameters) throws IOException {
        if (!isSignatureAlgorithmsExtensionAllowed(securityParameters.getNegotiatedVersion())) {
            securityParameters.clientSigAlgs = null;
            securityParameters.clientSigAlgsCert = null;
            return;
        }
        if (securityParameters.getClientSigAlgs() == null) {
            securityParameters.clientSigAlgs = getLegacySupportedSignatureAlgorithms();
        }
        if (securityParameters.getClientSigAlgsCert() == null) {
            securityParameters.clientSigAlgsCert = securityParameters.getClientSigAlgs();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void negotiatedVersionDTLSClient(TlsClientContext tlsClientContext, TlsClient tlsClient) throws IOException {
        SecurityParameters securityParametersHandshake = tlsClientContext.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParametersHandshake.getNegotiatedVersion();
        if (!ProtocolVersion.isSupportedDTLSVersionClient(negotiatedVersion)) {
            throw new TlsFatalAlert((short) 80);
        }
        negotiatedVersion(securityParametersHandshake);
        tlsClient.notifyServerVersion(negotiatedVersion);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void negotiatedVersionDTLSServer(TlsServerContext tlsServerContext) throws IOException {
        SecurityParameters securityParametersHandshake = tlsServerContext.getSecurityParametersHandshake();
        if (!ProtocolVersion.isSupportedDTLSVersionServer(securityParametersHandshake.getNegotiatedVersion())) {
            throw new TlsFatalAlert((short) 80);
        }
        negotiatedVersion(securityParametersHandshake);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void negotiatedVersionTLSClient(TlsClientContext tlsClientContext, TlsClient tlsClient) throws IOException {
        SecurityParameters securityParametersHandshake = tlsClientContext.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParametersHandshake.getNegotiatedVersion();
        if (!ProtocolVersion.isSupportedTLSVersionClient(negotiatedVersion)) {
            throw new TlsFatalAlert((short) 80);
        }
        negotiatedVersion(securityParametersHandshake);
        tlsClient.notifyServerVersion(negotiatedVersion);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void negotiatedVersionTLSServer(TlsServerContext tlsServerContext) throws IOException {
        SecurityParameters securityParametersHandshake = tlsServerContext.getSecurityParametersHandshake();
        if (!ProtocolVersion.isSupportedTLSVersionServer(securityParametersHandshake.getNegotiatedVersion())) {
            throw new TlsFatalAlert((short) 80);
        }
        negotiatedVersion(securityParametersHandshake);
    }

    static CertificateRequest normalizeCertificateRequest(CertificateRequest certificateRequest, short[] sArr) {
        if (containsAll(sArr, certificateRequest.getCertificateTypes())) {
            return certificateRequest;
        }
        short[] retainAll = retainAll(certificateRequest.getCertificateTypes(), sArr);
        if (retainAll.length < 1) {
            return null;
        }
        return new CertificateRequest(retainAll, certificateRequest.getSupportedSignatureAlgorithms(), certificateRequest.getCertificateAuthorities());
    }

    public static Vector parseSupportedSignatureAlgorithms(InputStream inputStream) throws IOException {
        int readUint16 = readUint16(inputStream);
        if (readUint16 < 2 || (readUint16 & 1) != 0) {
            throw new TlsFatalAlert((short) 50);
        }
        int i = readUint16 / 2;
        Vector vector = new Vector(i);
        for (int i2 = 0; i2 < i; i2++) {
            SignatureAndHashAlgorithm parse = SignatureAndHashAlgorithm.parse(inputStream);
            if (parse.getSignature() != 0) {
                vector.addElement(parse);
            }
        }
        return vector;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void processClientCertificate(TlsServerContext tlsServerContext, Certificate certificate, TlsKeyExchange tlsKeyExchange, TlsServer tlsServer) throws IOException {
        SecurityParameters securityParametersHandshake = tlsServerContext.getSecurityParametersHandshake();
        if (securityParametersHandshake.getPeerCertificate() != null) {
            throw new TlsFatalAlert((short) 10);
        }
        if (!isTLSv13(securityParametersHandshake.getNegotiatedVersion())) {
            if (certificate.isEmpty()) {
                tlsKeyExchange.skipClientCredentials();
            } else {
                tlsKeyExchange.processClientCertificate(certificate);
            }
        }
        securityParametersHandshake.peerCertificate = certificate;
        tlsServer.notifyClientCertificate(certificate);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static short processClientCertificateTypeExtension(Hashtable hashtable, Hashtable hashtable2, short s) throws IOException {
        short clientCertificateTypeExtensionServer = TlsExtensionsUtils.getClientCertificateTypeExtensionServer(hashtable2);
        if (clientCertificateTypeExtensionServer < 0) {
            return (short) 0;
        }
        if (CertificateType.isValid(clientCertificateTypeExtensionServer)) {
            short[] clientCertificateTypeExtensionClient = TlsExtensionsUtils.getClientCertificateTypeExtensionClient(hashtable);
            if (clientCertificateTypeExtensionClient == null || !contains(clientCertificateTypeExtensionClient, 0, clientCertificateTypeExtensionClient.length, clientCertificateTypeExtensionServer)) {
                throw new TlsFatalAlert(s, "Invalid selection for client_certificate_type");
            }
            return clientCertificateTypeExtensionServer;
        }
        throw new TlsFatalAlert(s, "Unknown value for client_certificate_type");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static short processClientCertificateTypeExtension13(Hashtable hashtable, Hashtable hashtable2, short s) throws IOException {
        return validateCertificateType13(processClientCertificateTypeExtension(hashtable, hashtable2, s), s);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static short processMaxFragmentLengthExtension(Hashtable hashtable, Hashtable hashtable2, short s) throws IOException {
        short maxFragmentLengthExtension = TlsExtensionsUtils.getMaxFragmentLengthExtension(hashtable2);
        if (maxFragmentLengthExtension < 0 || (MaxFragmentLength.isValid(maxFragmentLengthExtension) && (hashtable == null || maxFragmentLengthExtension == TlsExtensionsUtils.getMaxFragmentLengthExtension(hashtable)))) {
            return maxFragmentLengthExtension;
        }
        throw new TlsFatalAlert(s);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void processServerCertificate(TlsClientContext tlsClientContext, CertificateStatus certificateStatus, TlsKeyExchange tlsKeyExchange, TlsAuthentication tlsAuthentication, Hashtable hashtable, Hashtable hashtable2) throws IOException {
        SecurityParameters securityParametersHandshake = tlsClientContext.getSecurityParametersHandshake();
        boolean isTLSv13 = isTLSv13(securityParametersHandshake.getNegotiatedVersion());
        if (tlsAuthentication != null) {
            Certificate peerCertificate = securityParametersHandshake.getPeerCertificate();
            checkTlsFeatures(peerCertificate, hashtable, hashtable2);
            if (!isTLSv13) {
                tlsKeyExchange.processServerCertificate(peerCertificate);
            }
            tlsAuthentication.notifyServerCertificate(new TlsServerCertificateImpl(peerCertificate, certificateStatus));
        } else if (isTLSv13) {
            throw new TlsFatalAlert((short) 80);
        } else {
            if (securityParametersHandshake.isRenegotiating()) {
                throw new TlsFatalAlert((short) 40);
            }
            tlsKeyExchange.skipServerCredentials();
            securityParametersHandshake.tlsServerEndPoint = EMPTY_BYTES;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static short processServerCertificateTypeExtension(Hashtable hashtable, Hashtable hashtable2, short s) throws IOException {
        short serverCertificateTypeExtensionServer = TlsExtensionsUtils.getServerCertificateTypeExtensionServer(hashtable2);
        if (serverCertificateTypeExtensionServer < 0) {
            return (short) 0;
        }
        if (CertificateType.isValid(serverCertificateTypeExtensionServer)) {
            short[] serverCertificateTypeExtensionClient = TlsExtensionsUtils.getServerCertificateTypeExtensionClient(hashtable);
            if (serverCertificateTypeExtensionClient == null || !contains(serverCertificateTypeExtensionClient, 0, serverCertificateTypeExtensionClient.length, serverCertificateTypeExtensionServer)) {
                throw new TlsFatalAlert(s, "Invalid selection for server_certificate_type");
            }
            return serverCertificateTypeExtensionServer;
        }
        throw new TlsFatalAlert(s, "Unknown value for server_certificate_type");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static short processServerCertificateTypeExtension13(Hashtable hashtable, Hashtable hashtable2, short s) throws IOException {
        return validateCertificateType13(processServerCertificateTypeExtension(hashtable, hashtable2, s), s);
    }

    public static ASN1Primitive readASN1Object(byte[] bArr) throws IOException {
        ASN1InputStream aSN1InputStream = new ASN1InputStream(bArr);
        ASN1Primitive readObject = aSN1InputStream.readObject();
        if (readObject != null) {
            if (aSN1InputStream.readObject() == null) {
                return readObject;
            }
            throw new TlsFatalAlert((short) 50);
        }
        throw new TlsFatalAlert((short) 50);
    }

    public static byte[] readAllOrNothing(int i, InputStream inputStream) throws IOException {
        if (i < 1) {
            return EMPTY_BYTES;
        }
        byte[] bArr = new byte[i];
        int readFully = Streams.readFully(inputStream, bArr);
        if (readFully == 0) {
            return null;
        }
        if (readFully == i) {
            return bArr;
        }
        throw new EOFException();
    }

    public static ASN1Primitive readDERObject(byte[] bArr) throws IOException {
        ASN1Primitive readASN1Object = readASN1Object(bArr);
        requireDEREncoding(readASN1Object, bArr);
        return readASN1Object;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] readEncryptedPMS(TlsContext tlsContext, InputStream inputStream) throws IOException {
        return isSSL(tlsContext) ? SSL3Utils.readEncryptedPMS(inputStream) : readOpaque16(inputStream);
    }

    public static void readFully(byte[] bArr, InputStream inputStream) throws IOException {
        int length = bArr.length;
        if (length > 0 && length != Streams.readFully(inputStream, bArr)) {
            throw new EOFException();
        }
    }

    public static byte[] readFully(int i, InputStream inputStream) throws IOException {
        if (i < 1) {
            return EMPTY_BYTES;
        }
        byte[] bArr = new byte[i];
        if (i == Streams.readFully(inputStream, bArr)) {
            return bArr;
        }
        throw new EOFException();
    }

    public static int readInt32(byte[] bArr, int i) {
        return (bArr[i + 3] & UByte.MAX_VALUE) | (bArr[i] << 24) | ((bArr[i + 1] & UByte.MAX_VALUE) << 16) | ((bArr[i + 2] & UByte.MAX_VALUE) << 8);
    }

    public static byte[] readOpaque16(InputStream inputStream) throws IOException {
        return readFully(readUint16(inputStream), inputStream);
    }

    public static byte[] readOpaque16(InputStream inputStream, int i) throws IOException {
        int readUint16 = readUint16(inputStream);
        if (readUint16 >= i) {
            return readFully(readUint16, inputStream);
        }
        throw new TlsFatalAlert((short) 50);
    }

    public static byte[] readOpaque24(InputStream inputStream) throws IOException {
        return readFully(readUint24(inputStream), inputStream);
    }

    public static byte[] readOpaque24(InputStream inputStream, int i) throws IOException {
        int readUint24 = readUint24(inputStream);
        if (readUint24 >= i) {
            return readFully(readUint24, inputStream);
        }
        throw new TlsFatalAlert((short) 50);
    }

    public static byte[] readOpaque8(InputStream inputStream) throws IOException {
        return readFully(readUint8(inputStream), inputStream);
    }

    public static byte[] readOpaque8(InputStream inputStream, int i) throws IOException {
        short readUint8 = readUint8(inputStream);
        if (readUint8 >= i) {
            return readFully(readUint8, inputStream);
        }
        throw new TlsFatalAlert((short) 50);
    }

    public static byte[] readOpaque8(InputStream inputStream, int i, int i2) throws IOException {
        short readUint8 = readUint8(inputStream);
        if (readUint8 < i || i2 < readUint8) {
            throw new TlsFatalAlert((short) 50);
        }
        return readFully(readUint8, inputStream);
    }

    public static int readUint16(InputStream inputStream) throws IOException {
        int read = inputStream.read();
        int read2 = inputStream.read();
        if (read2 >= 0) {
            return read2 | (read << 8);
        }
        throw new EOFException();
    }

    public static int readUint16(byte[] bArr, int i) {
        return (bArr[i + 1] & UByte.MAX_VALUE) | ((bArr[i] & UByte.MAX_VALUE) << 8);
    }

    public static int[] readUint16Array(int i, InputStream inputStream) throws IOException {
        int[] iArr = new int[i];
        for (int i2 = 0; i2 < i; i2++) {
            iArr[i2] = readUint16(inputStream);
        }
        return iArr;
    }

    public static int readUint24(InputStream inputStream) throws IOException {
        int read = inputStream.read();
        int read2 = inputStream.read();
        int read3 = inputStream.read();
        if (read3 >= 0) {
            return read3 | (read << 16) | (read2 << 8);
        }
        throw new EOFException();
    }

    public static int readUint24(byte[] bArr, int i) {
        return (bArr[i + 2] & UByte.MAX_VALUE) | ((bArr[i] & UByte.MAX_VALUE) << 16) | ((bArr[i + 1] & UByte.MAX_VALUE) << 8);
    }

    public static long readUint32(InputStream inputStream) throws IOException {
        int read = inputStream.read();
        int read2 = inputStream.read();
        int read3 = inputStream.read();
        int read4 = inputStream.read();
        if (read4 >= 0) {
            return (read4 | (read << 24) | (read2 << 16) | (read3 << 8)) & BodyPartID.bodyIdMax;
        }
        throw new EOFException();
    }

    public static long readUint32(byte[] bArr, int i) {
        return ((bArr[i + 3] & UByte.MAX_VALUE) | ((bArr[i] & UByte.MAX_VALUE) << 24) | ((bArr[i + 1] & UByte.MAX_VALUE) << 16) | ((bArr[i + 2] & UByte.MAX_VALUE) << 8)) & BodyPartID.bodyIdMax;
    }

    public static long readUint48(InputStream inputStream) throws IOException {
        return ((readUint24(inputStream) & BodyPartID.bodyIdMax) << 24) | (BodyPartID.bodyIdMax & readUint24(inputStream));
    }

    public static long readUint48(byte[] bArr, int i) {
        int readUint24 = readUint24(bArr, i);
        return (readUint24(bArr, i + 3) & BodyPartID.bodyIdMax) | ((readUint24 & BodyPartID.bodyIdMax) << 24);
    }

    public static short readUint8(InputStream inputStream) throws IOException {
        int read = inputStream.read();
        if (read >= 0) {
            return (short) read;
        }
        throw new EOFException();
    }

    public static short readUint8(byte[] bArr, int i) {
        return (short) (bArr[i] & UByte.MAX_VALUE);
    }

    public static short[] readUint8Array(int i, InputStream inputStream) throws IOException {
        short[] sArr = new short[i];
        for (int i2 = 0; i2 < i; i2++) {
            sArr[i2] = readUint8(inputStream);
        }
        return sArr;
    }

    public static short[] readUint8ArrayWithUint8Length(InputStream inputStream, int i) throws IOException {
        short readUint8 = readUint8(inputStream);
        if (readUint8 >= i) {
            return readUint8Array(readUint8, inputStream);
        }
        throw new TlsFatalAlert((short) 50);
    }

    public static ProtocolVersion readVersion(InputStream inputStream) throws IOException {
        int read = inputStream.read();
        int read2 = inputStream.read();
        if (read2 >= 0) {
            return ProtocolVersion.get(read, read2);
        }
        throw new EOFException();
    }

    public static ProtocolVersion readVersion(byte[] bArr, int i) {
        return ProtocolVersion.get(bArr[i] & UByte.MAX_VALUE, bArr[i + 1] & UByte.MAX_VALUE);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TlsAuthentication receive13ServerCertificate(TlsClientContext tlsClientContext, TlsClient tlsClient, ByteArrayInputStream byteArrayInputStream, Hashtable hashtable) throws IOException {
        SecurityParameters securityParametersHandshake = tlsClientContext.getSecurityParametersHandshake();
        if (securityParametersHandshake.getPeerCertificate() == null) {
            Certificate parse = Certificate.parse(new Certificate.ParseOptions().setCertificateType(securityParametersHandshake.getServerCertificateType()).setMaxChainLength(tlsClient.getMaxCertificateChainLength()), tlsClientContext, byteArrayInputStream, null);
            TlsProtocol.assertEmpty(byteArrayInputStream);
            if (parse.getCertificateRequestContext().length <= 0) {
                if (parse.isEmpty()) {
                    throw new TlsFatalAlert((short) 50);
                }
                securityParametersHandshake.peerCertificate = parse;
                securityParametersHandshake.tlsServerEndPoint = null;
                TlsAuthentication authentication = tlsClient.getAuthentication();
                if (authentication != null) {
                    return authentication;
                }
                throw new TlsFatalAlert((short) 80);
            }
            throw new TlsFatalAlert((short) 47);
        }
        throw new TlsFatalAlert((short) 10);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TlsAuthentication receiveServerCertificate(TlsClientContext tlsClientContext, TlsClient tlsClient, ByteArrayInputStream byteArrayInputStream, Hashtable hashtable) throws IOException {
        SecurityParameters securityParametersHandshake = tlsClientContext.getSecurityParametersHandshake();
        if (KeyExchangeAlgorithm.isAnonymous(securityParametersHandshake.getKeyExchangeAlgorithm()) || securityParametersHandshake.getPeerCertificate() != null) {
            throw new TlsFatalAlert((short) 10);
        }
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        Certificate parse = Certificate.parse(new Certificate.ParseOptions().setCertificateType(securityParametersHandshake.getServerCertificateType()).setMaxChainLength(tlsClient.getMaxCertificateChainLength()), tlsClientContext, byteArrayInputStream, byteArrayOutputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        if (parse.isEmpty()) {
            throw new TlsFatalAlert((short) 50);
        }
        if (!securityParametersHandshake.isRenegotiating() || isSafeRenegotiationServerCertificate(tlsClientContext, parse)) {
            securityParametersHandshake.peerCertificate = parse;
            securityParametersHandshake.tlsServerEndPoint = byteArrayOutputStream.toByteArray();
            TlsAuthentication authentication = tlsClient.getAuthentication();
            if (authentication != null) {
                return authentication;
            }
            throw new TlsFatalAlert((short) 80);
        }
        throw new TlsFatalAlert((short) 46, "Server certificate changed unsafely in renegotiation handshake");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TlsCredentialedAgreement requireAgreementCredentials(TlsCredentials tlsCredentials) throws IOException {
        if (tlsCredentials instanceof TlsCredentialedAgreement) {
            return (TlsCredentialedAgreement) tlsCredentials;
        }
        throw new TlsFatalAlert((short) 80);
    }

    public static void requireDEREncoding(ASN1Object aSN1Object, byte[] bArr) throws IOException {
        if (!Arrays.areEqual(aSN1Object.getEncoded(ASN1Encoding.DER), bArr)) {
            throw new TlsFatalAlert((short) 50);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TlsCredentialedDecryptor requireDecryptorCredentials(TlsCredentials tlsCredentials) throws IOException {
        if (tlsCredentials instanceof TlsCredentialedDecryptor) {
            return (TlsCredentialedDecryptor) tlsCredentials;
        }
        throw new TlsFatalAlert((short) 80);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TlsCredentialedSigner requireSignerCredentials(TlsCredentials tlsCredentials) throws IOException {
        if (tlsCredentials instanceof TlsCredentialedSigner) {
            return (TlsCredentialedSigner) tlsCredentials;
        }
        throw new TlsFatalAlert((short) 80);
    }

    static short[] retainAll(short[] sArr, short[] sArr2) {
        short[] sArr3 = new short[Math.min(sArr.length, sArr2.length)];
        int i = 0;
        for (int i2 = 0; i2 < sArr2.length; i2++) {
            if (Arrays.contains(sArr, sArr2[i2])) {
                sArr3[i] = sArr2[i2];
                i++;
            }
        }
        return truncate(sArr3, i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static KeyShareEntry selectKeyShare(Vector vector, int i) {
        KeyShareEntry keyShareEntry;
        if (vector == null || 1 != vector.size() || (keyShareEntry = (KeyShareEntry) vector.elementAt(0)) == null || keyShareEntry.getNamedGroup() != i) {
            return null;
        }
        return keyShareEntry;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static KeyShareEntry selectKeyShare(TlsCrypto tlsCrypto, ProtocolVersion protocolVersion, Vector vector, int[] iArr, int[] iArr2) {
        if (vector == null || isNullOrEmpty(iArr) || isNullOrEmpty(iArr2)) {
            return null;
        }
        for (int i = 0; i < vector.size(); i++) {
            KeyShareEntry keyShareEntry = (KeyShareEntry) vector.elementAt(i);
            int namedGroup = keyShareEntry.getNamedGroup();
            if (NamedGroup.canBeNegotiated(namedGroup, protocolVersion) && Arrays.contains(iArr2, namedGroup) && Arrays.contains(iArr, namedGroup) && tlsCrypto.hasNamedGroup(namedGroup) && ((!NamedGroup.refersToAnECDHCurve(namedGroup) || tlsCrypto.hasECDHAgreement()) && ((!NamedGroup.refersToASpecificFiniteField(namedGroup) || tlsCrypto.hasDHAgreement()) && (!NamedGroup.refersToASpecificKem(namedGroup) || tlsCrypto.hasKemAgreement())))) {
                return keyShareEntry;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int selectKeyShareGroup(TlsCrypto tlsCrypto, ProtocolVersion protocolVersion, int[] iArr, int[] iArr2) {
        if (isNullOrEmpty(iArr) || isNullOrEmpty(iArr2)) {
            return -1;
        }
        for (int i : iArr) {
            if (NamedGroup.canBeNegotiated(i, protocolVersion) && Arrays.contains(iArr2, i) && tlsCrypto.hasNamedGroup(i) && ((!NamedGroup.refersToAnECDHCurve(i) || tlsCrypto.hasECDHAgreement()) && ((!NamedGroup.refersToASpecificFiniteField(i) || tlsCrypto.hasDHAgreement()) && (!NamedGroup.refersToASpecificKem(i) || tlsCrypto.hasKemAgreement())))) {
                return i;
            }
        }
        return -1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static OfferedPsks.SelectedConfig selectPreSharedKey(TlsServerContext tlsServerContext, TlsServer tlsServer, Hashtable hashtable, HandshakeMessageInput handshakeMessageInput, TlsHandshakeHash tlsHandshakeHash, boolean z) throws IOException {
        TlsPSKExternal externalPSK;
        int indexOfIdentity;
        byte[] calculateHash;
        OfferedPsks preSharedKeyClientHello = TlsExtensionsUtils.getPreSharedKeyClientHello(hashtable);
        if (preSharedKeyClientHello != null) {
            short[] pSKKeyExchangeModesExtension = TlsExtensionsUtils.getPSKKeyExchangeModesExtension(hashtable);
            if (isNullOrEmpty(pSKKeyExchangeModesExtension)) {
                throw new TlsFatalAlert(AlertDescription.missing_extension);
            }
            if (Arrays.contains(pSKKeyExchangeModesExtension, (short) 1) && (externalPSK = tlsServer.getExternalPSK(preSharedKeyClientHello.getIdentities())) != null && (indexOfIdentity = preSharedKeyClientHello.getIndexOfIdentity(new PskIdentity(externalPSK.getIdentity(), 0L))) >= 0) {
                byte[] bArr = (byte[]) preSharedKeyClientHello.getBinders().elementAt(indexOfIdentity);
                TlsCrypto crypto = tlsServerContext.getCrypto();
                TlsSecret pSKEarlySecret = getPSKEarlySecret(crypto, externalPSK);
                int hashForPRF = TlsCryptoUtils.getHashForPRF(externalPSK.getPRFAlgorithm());
                int bindersSize = preSharedKeyClientHello.getBindersSize();
                handshakeMessageInput.updateHashPrefix(tlsHandshakeHash, bindersSize);
                if (z) {
                    calculateHash = tlsHandshakeHash.getFinalHash(hashForPRF);
                } else {
                    TlsHash createHash = crypto.createHash(hashForPRF);
                    tlsHandshakeHash.copyBufferTo(new TlsHashOutputStream(createHash));
                    calculateHash = createHash.calculateHash();
                }
                handshakeMessageInput.updateHashSuffix(tlsHandshakeHash, bindersSize);
                if (Arrays.constantTimeAreEqual(calculatePSKBinder(crypto, true, hashForPRF, pSKEarlySecret, calculateHash), bArr)) {
                    return new OfferedPsks.SelectedConfig(indexOfIdentity, externalPSK, pSKKeyExchangeModesExtension, pSKEarlySecret);
                }
                return null;
            }
        }
        handshakeMessageInput.updateHash(tlsHandshakeHash);
        return null;
    }

    static void sendSignatureInput(TlsContext tlsContext, byte[] bArr, DigestInputBuffer digestInputBuffer, OutputStream outputStream) throws IOException {
        SecurityParameters securityParametersHandshake = tlsContext.getSecurityParametersHandshake();
        outputStream.write(Arrays.concatenate(securityParametersHandshake.getClientRandom(), securityParametersHandshake.getServerRandom()));
        if (bArr != null) {
            outputStream.write(bArr);
        }
        digestInputBuffer.copyInputTo(outputStream);
        outputStream.close();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TlsAuthentication skip13ServerCertificate(TlsClientContext tlsClientContext) throws IOException {
        SecurityParameters securityParametersHandshake = tlsClientContext.getSecurityParametersHandshake();
        if (securityParametersHandshake.getPeerCertificate() == null) {
            securityParametersHandshake.peerCertificate = null;
            securityParametersHandshake.tlsServerEndPoint = null;
            return null;
        }
        throw new TlsFatalAlert((short) 80);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void trackHashAlgorithmClient(TlsHandshakeHash tlsHandshakeHash, SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureAndHashAlgorithm);
        if (cryptoHashAlgorithm >= 0) {
            tlsHandshakeHash.trackHashAlgorithm(cryptoHashAlgorithm);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void trackHashAlgorithms(TlsHandshakeHash tlsHandshakeHash, Vector vector) {
        for (int i = 0; i < vector.size(); i++) {
            SignatureAndHashAlgorithm signatureAndHashAlgorithm = (SignatureAndHashAlgorithm) vector.elementAt(i);
            int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureAndHashAlgorithm);
            if (cryptoHashAlgorithm >= 0) {
                tlsHandshakeHash.trackHashAlgorithm(cryptoHashAlgorithm);
            } else if (8 == signatureAndHashAlgorithm.getHash()) {
                tlsHandshakeHash.forceBuffering();
            }
        }
    }

    static int[] truncate(int[] iArr, int i) {
        if (i >= iArr.length) {
            return iArr;
        }
        int[] iArr2 = new int[i];
        System.arraycopy(iArr, 0, iArr2, 0, i);
        return iArr2;
    }

    static short[] truncate(short[] sArr, int i) {
        if (i >= sArr.length) {
            return sArr;
        }
        short[] sArr2 = new short[i];
        System.arraycopy(sArr, 0, sArr2, 0, i);
        return sArr2;
    }

    private static TlsSecret update13TrafficSecret(SecurityParameters securityParameters, TlsSecret tlsSecret) throws IOException {
        return TlsCryptoUtils.hkdfExpandLabel(tlsSecret, securityParameters.getPRFCryptoHashAlgorithm(), "traffic upd", EMPTY_BYTES, securityParameters.getPRFHashLength());
    }

    private static void update13TrafficSecret(TlsContext tlsContext, boolean z) throws IOException {
        TlsSecret trafficSecretClient;
        SecurityParameters securityParametersConnection = tlsContext.getSecurityParametersConnection();
        if (z) {
            trafficSecretClient = securityParametersConnection.getTrafficSecretServer();
            securityParametersConnection.trafficSecretServer = update13TrafficSecret(securityParametersConnection, trafficSecretClient);
        } else {
            trafficSecretClient = securityParametersConnection.getTrafficSecretClient();
            securityParametersConnection.trafficSecretClient = update13TrafficSecret(securityParametersConnection, trafficSecretClient);
        }
        if (trafficSecretClient != null) {
            trafficSecretClient.destroy();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void update13TrafficSecretLocal(TlsContext tlsContext) throws IOException {
        update13TrafficSecret(tlsContext, tlsContext.isServer());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void update13TrafficSecretPeer(TlsContext tlsContext) throws IOException {
        update13TrafficSecret(tlsContext, !tlsContext.isServer());
    }

    static TlsCredentialedSigner validate13Credentials(TlsCredentials tlsCredentials) throws IOException {
        if (tlsCredentials == null) {
            return null;
        }
        if (tlsCredentials instanceof TlsCredentialedSigner) {
            return (TlsCredentialedSigner) tlsCredentials;
        }
        throw new TlsFatalAlert((short) 80);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static CertificateRequest validateCertificateRequest(CertificateRequest certificateRequest, TlsKeyExchange tlsKeyExchange) throws IOException {
        short[] clientCertificateTypes = tlsKeyExchange.getClientCertificateTypes();
        if (isNullOrEmpty(clientCertificateTypes)) {
            throw new TlsFatalAlert((short) 10);
        }
        CertificateRequest normalizeCertificateRequest = normalizeCertificateRequest(certificateRequest, clientCertificateTypes);
        if (normalizeCertificateRequest != null) {
            return normalizeCertificateRequest;
        }
        throw new TlsFatalAlert((short) 47);
    }

    private static short validateCertificateType13(short s, short s2) throws IOException {
        if (1 != s) {
            return s;
        }
        throw new TlsFatalAlert(s2, "The OpenPGP certificate type MUST NOT be used with TLS 1.3");
    }

    static TlsCredentials validateCredentials(TlsCredentials tlsCredentials) throws IOException {
        if (tlsCredentials == null || (tlsCredentials instanceof TlsCredentialedAgreement ? 1 : 0) + (tlsCredentials instanceof TlsCredentialedDecryptor ? 1 : 0) + (tlsCredentials instanceof TlsCredentialedSigner ? 1 : 0) == 1) {
            return tlsCredentials;
        }
        throw new TlsFatalAlert((short) 80);
    }

    public static Vector vectorOfOne(Object obj) {
        Vector vector = new Vector(1);
        vector.addElement(obj);
        return vector;
    }

    private static void verify13CertificateVerify(Vector vector, String str, TlsHandshakeHash tlsHandshakeHash, TlsCertificate tlsCertificate, CertificateVerify certificateVerify) throws IOException {
        try {
            int algorithm = certificateVerify.getAlgorithm();
            verifySupportedSignatureAlgorithm(vector, SignatureScheme.getSignatureAndHashAlgorithm(algorithm));
            Tls13Verifier createVerifier = tlsCertificate.createVerifier(algorithm);
            byte[] certificateVerifyHeader = getCertificateVerifyHeader(str);
            byte[] currentPRFHash = getCurrentPRFHash(tlsHandshakeHash);
            OutputStream outputStream = createVerifier.getOutputStream();
            outputStream.write(certificateVerifyHeader, 0, certificateVerifyHeader.length);
            outputStream.write(currentPRFHash, 0, currentPRFHash.length);
            if (!createVerifier.verifySignature(certificateVerify.getSignature())) {
                throw new TlsFatalAlert((short) 51);
            }
        } catch (TlsFatalAlert e) {
            throw e;
        } catch (Exception e2) {
            throw new TlsFatalAlert((short) 51, (Throwable) e2);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void verify13CertificateVerifyClient(TlsServerContext tlsServerContext, TlsHandshakeHash tlsHandshakeHash, CertificateVerify certificateVerify) throws IOException {
        SecurityParameters securityParametersHandshake = tlsServerContext.getSecurityParametersHandshake();
        verify13CertificateVerify(securityParametersHandshake.getServerSigAlgs(), "TLS 1.3, client CertificateVerify", tlsHandshakeHash, securityParametersHandshake.getPeerCertificate().getCertificateAt(0), certificateVerify);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void verify13CertificateVerifyServer(TlsClientContext tlsClientContext, TlsHandshakeHash tlsHandshakeHash, CertificateVerify certificateVerify) throws IOException {
        SecurityParameters securityParametersHandshake = tlsClientContext.getSecurityParametersHandshake();
        verify13CertificateVerify(securityParametersHandshake.getClientSigAlgs(), "TLS 1.3, server CertificateVerify", tlsHandshakeHash, securityParametersHandshake.getPeerCertificate().getCertificateAt(0), certificateVerify);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void verifyCertificateVerifyClient(TlsServerContext tlsServerContext, CertificateRequest certificateRequest, DigitallySigned digitallySigned, TlsHandshakeHash tlsHandshakeHash) throws IOException {
        short signature;
        short clientCertificateType;
        short s;
        boolean verifyRawSignature;
        SecurityParameters securityParametersHandshake = tlsServerContext.getSecurityParametersHandshake();
        TlsCertificate certificateAt = securityParametersHandshake.getPeerCertificate().getCertificateAt(0);
        SignatureAndHashAlgorithm algorithm = digitallySigned.getAlgorithm();
        if (algorithm == null) {
            signature = certificateAt.getLegacySignatureAlgorithm();
            clientCertificateType = getLegacyClientCertType(signature);
            s = 43;
        } else {
            verifySupportedSignatureAlgorithm(securityParametersHandshake.getServerSigAlgs(), algorithm);
            signature = algorithm.getSignature();
            clientCertificateType = SignatureAlgorithm.getClientCertificateType(signature);
            s = 47;
        }
        checkClientCertificateType(certificateRequest, clientCertificateType, s);
        try {
            TlsVerifier createVerifier = certificateAt.createVerifier(signature);
            TlsStreamVerifier streamVerifier = createVerifier.getStreamVerifier(digitallySigned);
            if (streamVerifier != null) {
                tlsHandshakeHash.copyBufferTo(streamVerifier.getOutputStream());
                verifyRawSignature = streamVerifier.isVerified();
            } else {
                verifyRawSignature = createVerifier.verifyRawSignature(digitallySigned, isTLSv12(tlsServerContext) ? tlsHandshakeHash.getFinalHash(SignatureScheme.getCryptoHashAlgorithm(algorithm)) : securityParametersHandshake.getSessionHash());
            }
            if (!verifyRawSignature) {
                throw new TlsFatalAlert((short) 51);
            }
        } catch (TlsFatalAlert e) {
            throw e;
        } catch (Exception e2) {
            throw new TlsFatalAlert((short) 51, (Throwable) e2);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void verifyServerKeyExchangeSignature(TlsContext tlsContext, InputStream inputStream, TlsCertificate tlsCertificate, byte[] bArr, DigestInputBuffer digestInputBuffer) throws IOException {
        short s;
        boolean verifyRawSignature;
        DigitallySigned parse = DigitallySigned.parse(tlsContext, inputStream);
        SecurityParameters securityParametersHandshake = tlsContext.getSecurityParametersHandshake();
        int keyExchangeAlgorithm = securityParametersHandshake.getKeyExchangeAlgorithm();
        SignatureAndHashAlgorithm algorithm = parse.getAlgorithm();
        if (algorithm == null) {
            s = getLegacySignatureAlgorithmServer(keyExchangeAlgorithm);
        } else {
            short signature = algorithm.getSignature();
            if (!isValidSignatureAlgorithmForServerKeyExchange(signature, keyExchangeAlgorithm)) {
                throw new TlsFatalAlert((short) 47);
            }
            verifySupportedSignatureAlgorithm(securityParametersHandshake.getClientSigAlgs(), algorithm);
            s = signature;
        }
        TlsVerifier createVerifier = tlsCertificate.createVerifier(s);
        TlsStreamVerifier streamVerifier = createVerifier.getStreamVerifier(parse);
        if (streamVerifier != null) {
            sendSignatureInput(tlsContext, bArr, digestInputBuffer, streamVerifier.getOutputStream());
            verifyRawSignature = streamVerifier.isVerified();
        } else {
            verifyRawSignature = createVerifier.verifyRawSignature(parse, calculateSignatureHash(tlsContext, algorithm, bArr, digestInputBuffer));
        }
        if (!verifyRawSignature) {
            throw new TlsFatalAlert((short) 51);
        }
    }

    public static void verifySupportedSignatureAlgorithm(Vector vector, SignatureAndHashAlgorithm signatureAndHashAlgorithm) throws IOException {
        verifySupportedSignatureAlgorithm(vector, signatureAndHashAlgorithm, (short) 47);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void verifySupportedSignatureAlgorithm(Vector vector, SignatureAndHashAlgorithm signatureAndHashAlgorithm, short s) throws IOException {
        if (vector == null || vector.size() < 1 || vector.size() >= 32768) {
            throw new IllegalArgumentException("'supportedSignatureAlgorithms' must have length from 1 to (2^15 - 1)");
        }
        if (signatureAndHashAlgorithm == null) {
            throw new IllegalArgumentException("'signatureAlgorithm' cannot be null");
        }
        if (signatureAndHashAlgorithm.getSignature() == 0 || !containsSignatureAlgorithm(vector, signatureAndHashAlgorithm)) {
            throw new TlsFatalAlert(s);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void writeDowngradeMarker(ProtocolVersion protocolVersion, byte[] bArr) throws IOException {
        byte[] bArr2;
        ProtocolVersion equivalentTLSVersion = protocolVersion.getEquivalentTLSVersion();
        if (ProtocolVersion.TLSv12 == equivalentTLSVersion) {
            bArr2 = DOWNGRADE_TLS12;
        } else if (!equivalentTLSVersion.isEqualOrEarlierVersionOf(ProtocolVersion.TLSv11)) {
            throw new TlsFatalAlert((short) 80);
        } else {
            bArr2 = DOWNGRADE_TLS11;
        }
        System.arraycopy(bArr2, 0, bArr, bArr.length - bArr2.length, bArr2.length);
    }

    static void writeEncryptedPMS(TlsContext tlsContext, byte[] bArr, OutputStream outputStream) throws IOException {
        if (isSSL(tlsContext)) {
            SSL3Utils.writeEncryptedPMS(bArr, outputStream);
        } else {
            writeOpaque16(bArr, outputStream);
        }
    }

    public static void writeGMTUnixTime(byte[] bArr, int i) {
        int currentTimeMillis = (int) (System.currentTimeMillis() / 1000);
        bArr[i] = (byte) (currentTimeMillis >>> 24);
        bArr[i + 1] = (byte) (currentTimeMillis >>> 16);
        bArr[i + 2] = (byte) (currentTimeMillis >>> 8);
        bArr[i + 3] = (byte) currentTimeMillis;
    }

    public static void writeOpaque16(byte[] bArr, OutputStream outputStream) throws IOException {
        checkUint16(bArr.length);
        writeUint16(bArr.length, outputStream);
        outputStream.write(bArr);
    }

    public static void writeOpaque16(byte[] bArr, byte[] bArr2, int i) throws IOException {
        checkUint16(bArr.length);
        writeUint16(bArr.length, bArr2, i);
        System.arraycopy(bArr, 0, bArr2, i + 2, bArr.length);
    }

    public static void writeOpaque24(byte[] bArr, OutputStream outputStream) throws IOException {
        checkUint24(bArr.length);
        writeUint24(bArr.length, outputStream);
        outputStream.write(bArr);
    }

    public static void writeOpaque24(byte[] bArr, byte[] bArr2, int i) throws IOException {
        checkUint24(bArr.length);
        writeUint24(bArr.length, bArr2, i);
        System.arraycopy(bArr, 0, bArr2, i + 3, bArr.length);
    }

    public static void writeOpaque8(byte[] bArr, OutputStream outputStream) throws IOException {
        checkUint8(bArr.length);
        writeUint8(bArr.length, outputStream);
        outputStream.write(bArr);
    }

    public static void writeOpaque8(byte[] bArr, byte[] bArr2, int i) throws IOException {
        checkUint8(bArr.length);
        writeUint8(bArr.length, bArr2, i);
        System.arraycopy(bArr, 0, bArr2, i + 1, bArr.length);
    }

    public static void writeUint16(int i, OutputStream outputStream) throws IOException {
        outputStream.write(i >>> 8);
        outputStream.write(i);
    }

    public static void writeUint16(int i, byte[] bArr, int i2) {
        bArr[i2] = (byte) (i >>> 8);
        bArr[i2 + 1] = (byte) i;
    }

    public static void writeUint16Array(int[] iArr, OutputStream outputStream) throws IOException {
        for (int i : iArr) {
            writeUint16(i, outputStream);
        }
    }

    public static void writeUint16Array(int[] iArr, byte[] bArr, int i) throws IOException {
        for (int i2 : iArr) {
            writeUint16(i2, bArr, i);
            i += 2;
        }
    }

    public static void writeUint16ArrayWithUint16Length(int[] iArr, OutputStream outputStream) throws IOException {
        int length = iArr.length * 2;
        checkUint16(length);
        writeUint16(length, outputStream);
        writeUint16Array(iArr, outputStream);
    }

    public static void writeUint16ArrayWithUint16Length(int[] iArr, byte[] bArr, int i) throws IOException {
        int length = iArr.length * 2;
        checkUint16(length);
        writeUint16(length, bArr, i);
        writeUint16Array(iArr, bArr, i + 2);
    }

    public static void writeUint16ArrayWithUint8Length(int[] iArr, byte[] bArr, int i) throws IOException {
        int length = iArr.length * 2;
        checkUint8(length);
        writeUint8(length, bArr, i);
        writeUint16Array(iArr, bArr, i + 1);
    }

    public static void writeUint24(int i, OutputStream outputStream) throws IOException {
        outputStream.write((byte) (i >>> 16));
        outputStream.write((byte) (i >>> 8));
        outputStream.write((byte) i);
    }

    public static void writeUint24(int i, byte[] bArr, int i2) {
        bArr[i2] = (byte) (i >>> 16);
        bArr[i2 + 1] = (byte) (i >>> 8);
        bArr[i2 + 2] = (byte) i;
    }

    public static void writeUint32(long j, OutputStream outputStream) throws IOException {
        outputStream.write((byte) (j >>> 24));
        outputStream.write((byte) (j >>> 16));
        outputStream.write((byte) (j >>> 8));
        outputStream.write((byte) j);
    }

    public static void writeUint32(long j, byte[] bArr, int i) {
        bArr[i] = (byte) (j >>> 24);
        bArr[i + 1] = (byte) (j >>> 16);
        bArr[i + 2] = (byte) (j >>> 8);
        bArr[i + 3] = (byte) j;
    }

    public static void writeUint48(long j, OutputStream outputStream) throws IOException {
        outputStream.write((byte) (j >>> 40));
        outputStream.write((byte) (j >>> 32));
        outputStream.write((byte) (j >>> 24));
        outputStream.write((byte) (j >>> 16));
        outputStream.write((byte) (j >>> 8));
        outputStream.write((byte) j);
    }

    public static void writeUint48(long j, byte[] bArr, int i) {
        bArr[i] = (byte) (j >>> 40);
        bArr[i + 1] = (byte) (j >>> 32);
        bArr[i + 2] = (byte) (j >>> 24);
        bArr[i + 3] = (byte) (j >>> 16);
        bArr[i + 4] = (byte) (j >>> 8);
        bArr[i + 5] = (byte) j;
    }

    public static void writeUint64(long j, OutputStream outputStream) throws IOException {
        outputStream.write((byte) (j >>> 56));
        outputStream.write((byte) (j >>> 48));
        outputStream.write((byte) (j >>> 40));
        outputStream.write((byte) (j >>> 32));
        outputStream.write((byte) (j >>> 24));
        outputStream.write((byte) (j >>> 16));
        outputStream.write((byte) (j >>> 8));
        outputStream.write((byte) j);
    }

    public static void writeUint64(long j, byte[] bArr, int i) {
        bArr[i] = (byte) (j >>> 56);
        bArr[i + 1] = (byte) (j >>> 48);
        bArr[i + 2] = (byte) (j >>> 40);
        bArr[i + 3] = (byte) (j >>> 32);
        bArr[i + 4] = (byte) (j >>> 24);
        bArr[i + 5] = (byte) (j >>> 16);
        bArr[i + 6] = (byte) (j >>> 8);
        bArr[i + 7] = (byte) j;
    }

    public static void writeUint8(int i, OutputStream outputStream) throws IOException {
        outputStream.write(i);
    }

    public static void writeUint8(int i, byte[] bArr, int i2) {
        bArr[i2] = (byte) i;
    }

    public static void writeUint8(short s, OutputStream outputStream) throws IOException {
        outputStream.write(s);
    }

    public static void writeUint8(short s, byte[] bArr, int i) {
        bArr[i] = (byte) s;
    }

    public static void writeUint8Array(short[] sArr, OutputStream outputStream) throws IOException {
        for (short s : sArr) {
            writeUint8(s, outputStream);
        }
    }

    public static void writeUint8Array(short[] sArr, byte[] bArr, int i) throws IOException {
        for (short s : sArr) {
            writeUint8(s, bArr, i);
            i++;
        }
    }

    public static void writeUint8ArrayWithUint8Length(short[] sArr, OutputStream outputStream) throws IOException {
        checkUint8(sArr.length);
        writeUint8(sArr.length, outputStream);
        writeUint8Array(sArr, outputStream);
    }

    public static void writeUint8ArrayWithUint8Length(short[] sArr, byte[] bArr, int i) throws IOException {
        checkUint8(sArr.length);
        writeUint8(sArr.length, bArr, i);
        writeUint8Array(sArr, bArr, i + 1);
    }

    public static void writeVersion(ProtocolVersion protocolVersion, OutputStream outputStream) throws IOException {
        outputStream.write(protocolVersion.getMajorVersion());
        outputStream.write(protocolVersion.getMinorVersion());
    }

    public static void writeVersion(ProtocolVersion protocolVersion, byte[] bArr, int i) {
        bArr[i] = (byte) protocolVersion.getMajorVersion();
        bArr[i + 1] = (byte) protocolVersion.getMinorVersion();
    }
}