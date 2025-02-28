package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

/* loaded from: classes2.dex */
public class TlsExtensionsUtils {
    public static final Integer EXT_application_layer_protocol_negotiation = Integers.valueOf(16);
    public static final Integer EXT_certificate_authorities = Integers.valueOf(47);
    public static final Integer EXT_client_certificate_type = Integers.valueOf(19);
    public static final Integer EXT_client_certificate_url = Integers.valueOf(2);
    public static final Integer EXT_compress_certificate = Integers.valueOf(27);
    public static final Integer EXT_connection_id = Integers.valueOf(54);
    public static final Integer EXT_cookie = Integers.valueOf(44);
    public static final Integer EXT_early_data = Integers.valueOf(42);
    public static final Integer EXT_ec_point_formats = Integers.valueOf(11);
    public static final Integer EXT_encrypt_then_mac = Integers.valueOf(22);
    public static final Integer EXT_extended_master_secret = Integers.valueOf(23);
    public static final Integer EXT_heartbeat = Integers.valueOf(15);
    public static final Integer EXT_key_share = Integers.valueOf(51);
    public static final Integer EXT_max_fragment_length = Integers.valueOf(1);
    public static final Integer EXT_oid_filters = Integers.valueOf(48);
    public static final Integer EXT_padding = Integers.valueOf(21);
    public static final Integer EXT_post_handshake_auth = Integers.valueOf(49);
    public static final Integer EXT_pre_shared_key = Integers.valueOf(41);
    public static final Integer EXT_psk_key_exchange_modes = Integers.valueOf(45);
    public static final Integer EXT_record_size_limit = Integers.valueOf(28);
    public static final Integer EXT_server_certificate_type = Integers.valueOf(20);
    public static final Integer EXT_server_name = Integers.valueOf(0);
    public static final Integer EXT_signature_algorithms = Integers.valueOf(13);
    public static final Integer EXT_signature_algorithms_cert = Integers.valueOf(50);
    public static final Integer EXT_status_request = Integers.valueOf(5);
    public static final Integer EXT_status_request_v2 = Integers.valueOf(17);
    public static final Integer EXT_supported_groups = Integers.valueOf(10);
    public static final Integer EXT_supported_versions = Integers.valueOf(43);
    public static final Integer EXT_truncated_hmac = Integers.valueOf(4);
    public static final Integer EXT_trusted_ca_keys = Integers.valueOf(3);

    public static void addALPNExtensionClient(Hashtable hashtable, Vector vector) throws IOException {
        hashtable.put(EXT_application_layer_protocol_negotiation, createALPNExtensionClient(vector));
    }

    public static void addALPNExtensionServer(Hashtable hashtable, ProtocolName protocolName) throws IOException {
        hashtable.put(EXT_application_layer_protocol_negotiation, createALPNExtensionServer(protocolName));
    }

    public static void addCertificateAuthoritiesExtension(Hashtable hashtable, Vector vector) throws IOException {
        hashtable.put(EXT_certificate_authorities, createCertificateAuthoritiesExtension(vector));
    }

    public static void addClientCertificateTypeExtensionClient(Hashtable hashtable, short[] sArr) throws IOException {
        hashtable.put(EXT_client_certificate_type, createCertificateTypeExtensionClient(sArr));
    }

    public static void addClientCertificateTypeExtensionServer(Hashtable hashtable, short s) throws IOException {
        hashtable.put(EXT_client_certificate_type, createCertificateTypeExtensionServer(s));
    }

    public static void addClientCertificateURLExtension(Hashtable hashtable) {
        hashtable.put(EXT_client_certificate_url, createClientCertificateURLExtension());
    }

    public static void addCompressCertificateExtension(Hashtable hashtable, int[] iArr) throws IOException {
        hashtable.put(EXT_compress_certificate, createCompressCertificateExtension(iArr));
    }

    public static void addConnectionIDExtension(Hashtable hashtable, byte[] bArr) throws IOException {
        hashtable.put(EXT_connection_id, createConnectionIDExtension(bArr));
    }

    public static void addCookieExtension(Hashtable hashtable, byte[] bArr) throws IOException {
        hashtable.put(EXT_cookie, createCookieExtension(bArr));
    }

    public static void addEarlyDataIndication(Hashtable hashtable) {
        hashtable.put(EXT_early_data, createEarlyDataIndication());
    }

    public static void addEarlyDataMaxSize(Hashtable hashtable, long j) throws IOException {
        hashtable.put(EXT_early_data, createEarlyDataMaxSize(j));
    }

    public static void addEmptyExtensionData(Hashtable hashtable, Integer num) {
        hashtable.put(num, createEmptyExtensionData());
    }

    public static void addEncryptThenMACExtension(Hashtable hashtable) {
        hashtable.put(EXT_encrypt_then_mac, createEncryptThenMACExtension());
    }

    public static void addExtendedMasterSecretExtension(Hashtable hashtable) {
        hashtable.put(EXT_extended_master_secret, createExtendedMasterSecretExtension());
    }

    public static void addHeartbeatExtension(Hashtable hashtable, HeartbeatExtension heartbeatExtension) throws IOException {
        hashtable.put(EXT_heartbeat, createHeartbeatExtension(heartbeatExtension));
    }

    public static void addKeyShareClientHello(Hashtable hashtable, Vector vector) throws IOException {
        hashtable.put(EXT_key_share, createKeyShareClientHello(vector));
    }

    public static void addKeyShareHelloRetryRequest(Hashtable hashtable, int i) throws IOException {
        hashtable.put(EXT_key_share, createKeyShareHelloRetryRequest(i));
    }

    public static void addKeyShareServerHello(Hashtable hashtable, KeyShareEntry keyShareEntry) throws IOException {
        hashtable.put(EXT_key_share, createKeyShareServerHello(keyShareEntry));
    }

    public static void addMaxFragmentLengthExtension(Hashtable hashtable, short s) throws IOException {
        hashtable.put(EXT_max_fragment_length, createMaxFragmentLengthExtension(s));
    }

    public static void addOIDFiltersExtension(Hashtable hashtable, Hashtable hashtable2) throws IOException {
        hashtable.put(EXT_oid_filters, createOIDFiltersExtension(hashtable2));
    }

    public static void addPSKKeyExchangeModesExtension(Hashtable hashtable, short[] sArr) throws IOException {
        hashtable.put(EXT_psk_key_exchange_modes, createPSKKeyExchangeModesExtension(sArr));
    }

    public static void addPaddingExtension(Hashtable hashtable, int i) throws IOException {
        hashtable.put(EXT_padding, createPaddingExtension(i));
    }

    public static void addPostHandshakeAuthExtension(Hashtable hashtable) {
        hashtable.put(EXT_post_handshake_auth, createPostHandshakeAuthExtension());
    }

    public static void addPreSharedKeyClientHello(Hashtable hashtable, OfferedPsks offeredPsks) throws IOException {
        hashtable.put(EXT_pre_shared_key, createPreSharedKeyClientHello(offeredPsks));
    }

    public static void addPreSharedKeyServerHello(Hashtable hashtable, int i) throws IOException {
        hashtable.put(EXT_pre_shared_key, createPreSharedKeyServerHello(i));
    }

    public static void addRecordSizeLimitExtension(Hashtable hashtable, int i) throws IOException {
        hashtable.put(EXT_record_size_limit, createRecordSizeLimitExtension(i));
    }

    public static void addServerCertificateTypeExtensionClient(Hashtable hashtable, short[] sArr) throws IOException {
        hashtable.put(EXT_server_certificate_type, createCertificateTypeExtensionClient(sArr));
    }

    public static void addServerCertificateTypeExtensionServer(Hashtable hashtable, short s) throws IOException {
        hashtable.put(EXT_server_certificate_type, createCertificateTypeExtensionServer(s));
    }

    public static void addServerNameExtensionClient(Hashtable hashtable, Vector vector) throws IOException {
        hashtable.put(EXT_server_name, createServerNameExtensionClient(vector));
    }

    public static void addServerNameExtensionServer(Hashtable hashtable) throws IOException {
        hashtable.put(EXT_server_name, createServerNameExtensionServer());
    }

    public static void addSignatureAlgorithmsCertExtension(Hashtable hashtable, Vector vector) throws IOException {
        hashtable.put(EXT_signature_algorithms_cert, createSignatureAlgorithmsCertExtension(vector));
    }

    public static void addSignatureAlgorithmsExtension(Hashtable hashtable, Vector vector) throws IOException {
        hashtable.put(EXT_signature_algorithms, createSignatureAlgorithmsExtension(vector));
    }

    public static void addStatusRequestExtension(Hashtable hashtable, CertificateStatusRequest certificateStatusRequest) throws IOException {
        hashtable.put(EXT_status_request, createStatusRequestExtension(certificateStatusRequest));
    }

    public static void addStatusRequestV2Extension(Hashtable hashtable, Vector vector) throws IOException {
        hashtable.put(EXT_status_request_v2, createStatusRequestV2Extension(vector));
    }

    public static void addSupportedGroupsExtension(Hashtable hashtable, Vector vector) throws IOException {
        hashtable.put(EXT_supported_groups, createSupportedGroupsExtension(vector));
    }

    public static void addSupportedPointFormatsExtension(Hashtable hashtable, short[] sArr) throws IOException {
        hashtable.put(EXT_ec_point_formats, createSupportedPointFormatsExtension(sArr));
    }

    public static void addSupportedVersionsExtensionClient(Hashtable hashtable, ProtocolVersion[] protocolVersionArr) throws IOException {
        hashtable.put(EXT_supported_versions, createSupportedVersionsExtensionClient(protocolVersionArr));
    }

    public static void addSupportedVersionsExtensionServer(Hashtable hashtable, ProtocolVersion protocolVersion) throws IOException {
        hashtable.put(EXT_supported_versions, createSupportedVersionsExtensionServer(protocolVersion));
    }

    public static void addTruncatedHMacExtension(Hashtable hashtable) {
        hashtable.put(EXT_truncated_hmac, createTruncatedHMacExtension());
    }

    public static void addTrustedCAKeysExtensionClient(Hashtable hashtable, Vector vector) throws IOException {
        hashtable.put(EXT_trusted_ca_keys, createTrustedCAKeysExtensionClient(vector));
    }

    public static void addTrustedCAKeysExtensionServer(Hashtable hashtable) {
        hashtable.put(EXT_trusted_ca_keys, createTrustedCAKeysExtensionServer());
    }

    public static byte[] createALPNExtensionClient(Vector vector) throws IOException {
        if (vector == null || vector.size() < 1) {
            throw new TlsFatalAlert((short) 80);
        }
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint16(0, byteArrayOutputStream);
        for (int i = 0; i < vector.size(); i++) {
            ((ProtocolName) vector.elementAt(i)).encode(byteArrayOutputStream);
        }
        return patchOpaque16(byteArrayOutputStream);
    }

    public static byte[] createALPNExtensionServer(ProtocolName protocolName) throws IOException {
        Vector vector = new Vector();
        vector.addElement(protocolName);
        return createALPNExtensionClient(vector);
    }

    public static byte[] createCertificateAuthoritiesExtension(Vector vector) throws IOException {
        if (vector == null || vector.isEmpty()) {
            throw new TlsFatalAlert((short) 80);
        }
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint16(0, byteArrayOutputStream);
        for (int i = 0; i < vector.size(); i++) {
            TlsUtils.writeOpaque16(((X500Name) vector.elementAt(i)).getEncoded(ASN1Encoding.DER), byteArrayOutputStream);
        }
        return patchOpaque16(byteArrayOutputStream);
    }

    public static byte[] createCertificateTypeExtensionClient(short[] sArr) throws IOException {
        if (TlsUtils.isNullOrEmpty(sArr) || sArr.length > 255) {
            throw new TlsFatalAlert((short) 80);
        }
        return TlsUtils.encodeUint8ArrayWithUint8Length(sArr);
    }

    public static byte[] createCertificateTypeExtensionServer(short s) throws IOException {
        return TlsUtils.encodeUint8(s);
    }

    public static byte[] createClientCertificateURLExtension() {
        return createEmptyExtensionData();
    }

    public static byte[] createCompressCertificateExtension(int[] iArr) throws IOException {
        if (TlsUtils.isNullOrEmpty(iArr) || iArr.length > 127) {
            throw new TlsFatalAlert((short) 80);
        }
        return TlsUtils.encodeUint16ArrayWithUint8Length(iArr);
    }

    public static byte[] createConnectionIDExtension(byte[] bArr) throws IOException {
        if (bArr != null) {
            return TlsUtils.encodeOpaque8(bArr);
        }
        throw new TlsFatalAlert((short) 80);
    }

    public static byte[] createCookieExtension(byte[] bArr) throws IOException {
        if (TlsUtils.isNullOrEmpty(bArr) || bArr.length >= 65536) {
            throw new TlsFatalAlert((short) 80);
        }
        return TlsUtils.encodeOpaque16(bArr);
    }

    public static byte[] createEarlyDataIndication() {
        return createEmptyExtensionData();
    }

    public static byte[] createEarlyDataMaxSize(long j) throws IOException {
        return TlsUtils.encodeUint32(j);
    }

    public static byte[] createEmptyExtensionData() {
        return TlsUtils.EMPTY_BYTES;
    }

    public static byte[] createEncryptThenMACExtension() {
        return createEmptyExtensionData();
    }

    public static byte[] createExtendedMasterSecretExtension() {
        return createEmptyExtensionData();
    }

    public static byte[] createHeartbeatExtension(HeartbeatExtension heartbeatExtension) throws IOException {
        if (heartbeatExtension != null) {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            heartbeatExtension.encode(byteArrayOutputStream);
            return byteArrayOutputStream.toByteArray();
        }
        throw new TlsFatalAlert((short) 80);
    }

    public static byte[] createKeyShareClientHello(Vector vector) throws IOException {
        if (vector == null || vector.isEmpty()) {
            return TlsUtils.encodeUint16(0);
        }
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint16(0, byteArrayOutputStream);
        for (int i = 0; i < vector.size(); i++) {
            ((KeyShareEntry) vector.elementAt(i)).encode(byteArrayOutputStream);
        }
        return patchOpaque16(byteArrayOutputStream);
    }

    public static byte[] createKeyShareHelloRetryRequest(int i) throws IOException {
        return TlsUtils.encodeUint16(i);
    }

    public static byte[] createKeyShareServerHello(KeyShareEntry keyShareEntry) throws IOException {
        if (keyShareEntry != null) {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            keyShareEntry.encode(byteArrayOutputStream);
            return byteArrayOutputStream.toByteArray();
        }
        throw new TlsFatalAlert((short) 80);
    }

    public static byte[] createMaxFragmentLengthExtension(short s) throws IOException {
        return TlsUtils.encodeUint8(s);
    }

    public static byte[] createOIDFiltersExtension(Hashtable hashtable) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint16(0, byteArrayOutputStream);
        if (hashtable != null) {
            Enumeration keys = hashtable.keys();
            while (keys.hasMoreElements()) {
                ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) keys.nextElement();
                byte[] bArr = (byte[]) hashtable.get(aSN1ObjectIdentifier);
                if (aSN1ObjectIdentifier == null || bArr == null) {
                    throw new TlsFatalAlert((short) 80);
                }
                TlsUtils.writeOpaque8(aSN1ObjectIdentifier.getEncoded(ASN1Encoding.DER), byteArrayOutputStream);
                TlsUtils.writeOpaque16(bArr, byteArrayOutputStream);
            }
        }
        return patchOpaque16(byteArrayOutputStream);
    }

    public static byte[] createPSKKeyExchangeModesExtension(short[] sArr) throws IOException {
        if (TlsUtils.isNullOrEmpty(sArr) || sArr.length > 255) {
            throw new TlsFatalAlert((short) 80);
        }
        return TlsUtils.encodeUint8ArrayWithUint8Length(sArr);
    }

    public static byte[] createPaddingExtension(int i) throws IOException {
        TlsUtils.checkUint16(i);
        return new byte[i];
    }

    public static byte[] createPostHandshakeAuthExtension() {
        return createEmptyExtensionData();
    }

    public static byte[] createPreSharedKeyClientHello(OfferedPsks offeredPsks) throws IOException {
        if (offeredPsks != null) {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            offeredPsks.encode(byteArrayOutputStream);
            return byteArrayOutputStream.toByteArray();
        }
        throw new TlsFatalAlert((short) 80);
    }

    public static byte[] createPreSharedKeyServerHello(int i) throws IOException {
        return TlsUtils.encodeUint16(i);
    }

    public static byte[] createRecordSizeLimitExtension(int i) throws IOException {
        if (i >= 64) {
            return TlsUtils.encodeUint16(i);
        }
        throw new TlsFatalAlert((short) 80);
    }

    public static byte[] createServerNameExtensionClient(Vector vector) throws IOException {
        if (vector != null) {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            new ServerNameList(vector).encode(byteArrayOutputStream);
            return byteArrayOutputStream.toByteArray();
        }
        throw new TlsFatalAlert((short) 80);
    }

    public static byte[] createServerNameExtensionServer() {
        return createEmptyExtensionData();
    }

    public static byte[] createSignatureAlgorithmsCertExtension(Vector vector) throws IOException {
        return createSignatureAlgorithmsExtension(vector);
    }

    public static byte[] createSignatureAlgorithmsExtension(Vector vector) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.encodeSupportedSignatureAlgorithms(vector, byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    public static byte[] createStatusRequestExtension(CertificateStatusRequest certificateStatusRequest) throws IOException {
        if (certificateStatusRequest != null) {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            certificateStatusRequest.encode(byteArrayOutputStream);
            return byteArrayOutputStream.toByteArray();
        }
        throw new TlsFatalAlert((short) 80);
    }

    public static byte[] createStatusRequestV2Extension(Vector vector) throws IOException {
        if (vector == null || vector.isEmpty()) {
            throw new TlsFatalAlert((short) 80);
        }
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint16(0, byteArrayOutputStream);
        for (int i = 0; i < vector.size(); i++) {
            ((CertificateStatusRequestItemV2) vector.elementAt(i)).encode(byteArrayOutputStream);
        }
        return patchOpaque16(byteArrayOutputStream);
    }

    public static byte[] createSupportedGroupsExtension(Vector vector) throws IOException {
        if (vector == null || vector.isEmpty()) {
            throw new TlsFatalAlert((short) 80);
        }
        int size = vector.size();
        int[] iArr = new int[size];
        for (int i = 0; i < size; i++) {
            iArr[i] = ((Integer) vector.elementAt(i)).intValue();
        }
        return TlsUtils.encodeUint16ArrayWithUint16Length(iArr);
    }

    public static byte[] createSupportedPointFormatsExtension(short[] sArr) throws IOException {
        if (sArr == null || !Arrays.contains(sArr, (short) 0)) {
            sArr = Arrays.prepend(sArr, (short) 0);
        }
        return TlsUtils.encodeUint8ArrayWithUint8Length(sArr);
    }

    public static byte[] createSupportedVersionsExtensionClient(ProtocolVersion[] protocolVersionArr) throws IOException {
        if (TlsUtils.isNullOrEmpty(protocolVersionArr) || protocolVersionArr.length > 127) {
            throw new TlsFatalAlert((short) 80);
        }
        int length = protocolVersionArr.length;
        int i = length * 2;
        byte[] bArr = new byte[i + 1];
        TlsUtils.writeUint8(i, bArr, 0);
        for (int i2 = 0; i2 < length; i2++) {
            TlsUtils.writeVersion(protocolVersionArr[i2], bArr, (i2 * 2) + 1);
        }
        return bArr;
    }

    public static byte[] createSupportedVersionsExtensionServer(ProtocolVersion protocolVersion) throws IOException {
        return TlsUtils.encodeVersion(protocolVersion);
    }

    public static byte[] createTruncatedHMacExtension() {
        return createEmptyExtensionData();
    }

    public static byte[] createTrustedCAKeysExtensionClient(Vector vector) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint16(0, byteArrayOutputStream);
        if (vector != null) {
            for (int i = 0; i < vector.size(); i++) {
                ((TrustedAuthority) vector.elementAt(i)).encode(byteArrayOutputStream);
            }
        }
        return patchOpaque16(byteArrayOutputStream);
    }

    public static byte[] createTrustedCAKeysExtensionServer() {
        return createEmptyExtensionData();
    }

    public static Hashtable ensureExtensionsInitialised(Hashtable hashtable) {
        return hashtable == null ? new Hashtable() : hashtable;
    }

    public static Vector getALPNExtensionClient(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_application_layer_protocol_negotiation);
        if (extensionData == null) {
            return null;
        }
        return readALPNExtensionClient(extensionData);
    }

    public static ProtocolName getALPNExtensionServer(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_application_layer_protocol_negotiation);
        if (extensionData == null) {
            return null;
        }
        return readALPNExtensionServer(extensionData);
    }

    public static Vector getCertificateAuthoritiesExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_certificate_authorities);
        if (extensionData == null) {
            return null;
        }
        return readCertificateAuthoritiesExtension(extensionData);
    }

    public static short[] getClientCertificateTypeExtensionClient(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_client_certificate_type);
        if (extensionData == null) {
            return null;
        }
        return readCertificateTypeExtensionClient(extensionData);
    }

    public static short getClientCertificateTypeExtensionServer(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_client_certificate_type);
        if (extensionData == null) {
            return (short) -1;
        }
        return readCertificateTypeExtensionServer(extensionData);
    }

    public static short getClientCertificateTypeExtensionServer(Hashtable hashtable, short s) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_client_certificate_type);
        return extensionData == null ? s : readCertificateTypeExtensionServer(extensionData);
    }

    public static int[] getCompressCertificateExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_compress_certificate);
        if (extensionData == null) {
            return null;
        }
        return readCompressCertificateExtension(extensionData);
    }

    public static byte[] getConnectionIDExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_connection_id);
        if (extensionData == null) {
            return null;
        }
        return readConnectionIDExtension(extensionData);
    }

    public static byte[] getCookieExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_cookie);
        if (extensionData == null) {
            return null;
        }
        return readCookieExtension(extensionData);
    }

    public static long getEarlyDataMaxSize(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_early_data);
        if (extensionData == null) {
            return -1L;
        }
        return readEarlyDataMaxSize(extensionData);
    }

    public static HeartbeatExtension getHeartbeatExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_heartbeat);
        if (extensionData == null) {
            return null;
        }
        return readHeartbeatExtension(extensionData);
    }

    public static Vector getKeyShareClientHello(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_key_share);
        if (extensionData == null) {
            return null;
        }
        return readKeyShareClientHello(extensionData);
    }

    public static int getKeyShareHelloRetryRequest(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_key_share);
        if (extensionData == null) {
            return -1;
        }
        return readKeyShareHelloRetryRequest(extensionData);
    }

    public static KeyShareEntry getKeyShareServerHello(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_key_share);
        if (extensionData == null) {
            return null;
        }
        return readKeyShareServerHello(extensionData);
    }

    public static short getMaxFragmentLengthExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_max_fragment_length);
        if (extensionData == null) {
            return (short) -1;
        }
        return readMaxFragmentLengthExtension(extensionData);
    }

    public static Hashtable getOIDFiltersExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_oid_filters);
        if (extensionData == null) {
            return null;
        }
        return readOIDFiltersExtension(extensionData);
    }

    public static short[] getPSKKeyExchangeModesExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_psk_key_exchange_modes);
        if (extensionData == null) {
            return null;
        }
        return readPSKKeyExchangeModesExtension(extensionData);
    }

    public static int getPaddingExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_padding);
        if (extensionData == null) {
            return -1;
        }
        return readPaddingExtension(extensionData);
    }

    public static OfferedPsks getPreSharedKeyClientHello(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_pre_shared_key);
        if (extensionData == null) {
            return null;
        }
        return readPreSharedKeyClientHello(extensionData);
    }

    public static int getPreSharedKeyServerHello(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_pre_shared_key);
        if (extensionData == null) {
            return -1;
        }
        return readPreSharedKeyServerHello(extensionData);
    }

    public static int getRecordSizeLimitExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_record_size_limit);
        if (extensionData == null) {
            return -1;
        }
        return readRecordSizeLimitExtension(extensionData);
    }

    public static short[] getServerCertificateTypeExtensionClient(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_server_certificate_type);
        if (extensionData == null) {
            return null;
        }
        return readCertificateTypeExtensionClient(extensionData);
    }

    public static short getServerCertificateTypeExtensionServer(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_server_certificate_type);
        if (extensionData == null) {
            return (short) -1;
        }
        return readCertificateTypeExtensionServer(extensionData);
    }

    public static short getServerCertificateTypeExtensionServer(Hashtable hashtable, short s) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_server_certificate_type);
        return extensionData == null ? s : readCertificateTypeExtensionServer(extensionData);
    }

    public static Vector getServerNameExtensionClient(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_server_name);
        if (extensionData == null) {
            return null;
        }
        return readServerNameExtensionClient(extensionData);
    }

    public static Vector getSignatureAlgorithmsCertExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_signature_algorithms_cert);
        if (extensionData == null) {
            return null;
        }
        return readSignatureAlgorithmsCertExtension(extensionData);
    }

    public static Vector getSignatureAlgorithmsExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_signature_algorithms);
        if (extensionData == null) {
            return null;
        }
        return readSignatureAlgorithmsExtension(extensionData);
    }

    public static CertificateStatusRequest getStatusRequestExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_status_request);
        if (extensionData == null) {
            return null;
        }
        return readStatusRequestExtension(extensionData);
    }

    public static Vector getStatusRequestV2Extension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_status_request_v2);
        if (extensionData == null) {
            return null;
        }
        return readStatusRequestV2Extension(extensionData);
    }

    public static int[] getSupportedGroupsExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_supported_groups);
        if (extensionData == null) {
            return null;
        }
        return readSupportedGroupsExtension(extensionData);
    }

    public static short[] getSupportedPointFormatsExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_ec_point_formats);
        if (extensionData == null) {
            return null;
        }
        return readSupportedPointFormatsExtension(extensionData);
    }

    public static ProtocolVersion[] getSupportedVersionsExtensionClient(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_supported_versions);
        if (extensionData == null) {
            return null;
        }
        return readSupportedVersionsExtensionClient(extensionData);
    }

    public static ProtocolVersion getSupportedVersionsExtensionServer(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_supported_versions);
        if (extensionData == null) {
            return null;
        }
        return readSupportedVersionsExtensionServer(extensionData);
    }

    public static Vector getTrustedCAKeysExtensionClient(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_trusted_ca_keys);
        if (extensionData == null) {
            return null;
        }
        return readTrustedCAKeysExtensionClient(extensionData);
    }

    public static boolean hasClientCertificateURLExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_client_certificate_url);
        if (extensionData == null) {
            return false;
        }
        return readClientCertificateURLExtension(extensionData);
    }

    public static boolean hasEarlyDataIndication(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_early_data);
        if (extensionData == null) {
            return false;
        }
        return readEarlyDataIndication(extensionData);
    }

    public static boolean hasEncryptThenMACExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_encrypt_then_mac);
        if (extensionData == null) {
            return false;
        }
        return readEncryptThenMACExtension(extensionData);
    }

    public static boolean hasExtendedMasterSecretExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_extended_master_secret);
        if (extensionData == null) {
            return false;
        }
        return readExtendedMasterSecretExtension(extensionData);
    }

    public static boolean hasPostHandshakeAuthExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_post_handshake_auth);
        if (extensionData == null) {
            return false;
        }
        return readPostHandshakeAuthExtension(extensionData);
    }

    public static boolean hasServerNameExtensionServer(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_server_name);
        if (extensionData == null) {
            return false;
        }
        return readServerNameExtensionServer(extensionData);
    }

    public static boolean hasTruncatedHMacExtension(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_truncated_hmac);
        if (extensionData == null) {
            return false;
        }
        return readTruncatedHMacExtension(extensionData);
    }

    public static boolean hasTrustedCAKeysExtensionServer(Hashtable hashtable) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(hashtable, EXT_trusted_ca_keys);
        if (extensionData == null) {
            return false;
        }
        return readTrustedCAKeysExtensionServer(extensionData);
    }

    private static byte[] patchOpaque16(ByteArrayOutputStream byteArrayOutputStream) throws IOException {
        int size = byteArrayOutputStream.size() - 2;
        TlsUtils.checkUint16(size);
        byte[] byteArray = byteArrayOutputStream.toByteArray();
        TlsUtils.writeUint16(size, byteArray, 0);
        return byteArray;
    }

    public static Vector readALPNExtensionClient(byte[] bArr) throws IOException {
        if (bArr != null) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
            if (TlsUtils.readUint16(byteArrayInputStream) == bArr.length - 2) {
                Vector vector = new Vector();
                while (byteArrayInputStream.available() > 0) {
                    vector.addElement(ProtocolName.parse(byteArrayInputStream));
                }
                return vector;
            }
            throw new TlsFatalAlert((short) 50);
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static ProtocolName readALPNExtensionServer(byte[] bArr) throws IOException {
        Vector readALPNExtensionClient = readALPNExtensionClient(bArr);
        if (readALPNExtensionClient.size() == 1) {
            return (ProtocolName) readALPNExtensionClient.elementAt(0);
        }
        throw new TlsFatalAlert((short) 50);
    }

    public static Vector readCertificateAuthoritiesExtension(byte[] bArr) throws IOException {
        if (bArr != null) {
            if (bArr.length >= 5) {
                ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
                if (TlsUtils.readUint16(byteArrayInputStream) == bArr.length - 2) {
                    Vector vector = new Vector();
                    while (byteArrayInputStream.available() > 0) {
                        byte[] readOpaque16 = TlsUtils.readOpaque16(byteArrayInputStream, 1);
                        X500Name x500Name = X500Name.getInstance(TlsUtils.readASN1Object(readOpaque16));
                        TlsUtils.requireDEREncoding(x500Name, readOpaque16);
                        vector.addElement(x500Name);
                    }
                    return vector;
                }
                throw new TlsFatalAlert((short) 50);
            }
            throw new TlsFatalAlert((short) 50);
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static short[] readCertificateTypeExtensionClient(byte[] bArr) throws IOException {
        short[] decodeUint8ArrayWithUint8Length = TlsUtils.decodeUint8ArrayWithUint8Length(bArr);
        if (decodeUint8ArrayWithUint8Length.length >= 1) {
            return decodeUint8ArrayWithUint8Length;
        }
        throw new TlsFatalAlert((short) 50);
    }

    public static short readCertificateTypeExtensionServer(byte[] bArr) throws IOException {
        return TlsUtils.decodeUint8(bArr);
    }

    public static boolean readClientCertificateURLExtension(byte[] bArr) throws IOException {
        return readEmptyExtensionData(bArr);
    }

    public static int[] readCompressCertificateExtension(byte[] bArr) throws IOException {
        int[] decodeUint16ArrayWithUint8Length = TlsUtils.decodeUint16ArrayWithUint8Length(bArr);
        if (decodeUint16ArrayWithUint8Length.length >= 1) {
            return decodeUint16ArrayWithUint8Length;
        }
        throw new TlsFatalAlert((short) 50);
    }

    public static byte[] readConnectionIDExtension(byte[] bArr) throws IOException {
        return TlsUtils.decodeOpaque8(bArr);
    }

    public static byte[] readCookieExtension(byte[] bArr) throws IOException {
        return TlsUtils.decodeOpaque16(bArr, 1);
    }

    public static boolean readEarlyDataIndication(byte[] bArr) throws IOException {
        return readEmptyExtensionData(bArr);
    }

    public static long readEarlyDataMaxSize(byte[] bArr) throws IOException {
        return TlsUtils.decodeUint32(bArr);
    }

    private static boolean readEmptyExtensionData(byte[] bArr) throws IOException {
        if (bArr != null) {
            if (bArr.length == 0) {
                return true;
            }
            throw new TlsFatalAlert((short) 47);
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static boolean readEncryptThenMACExtension(byte[] bArr) throws IOException {
        return readEmptyExtensionData(bArr);
    }

    public static boolean readExtendedMasterSecretExtension(byte[] bArr) throws IOException {
        return readEmptyExtensionData(bArr);
    }

    public static HeartbeatExtension readHeartbeatExtension(byte[] bArr) throws IOException {
        if (bArr != null) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
            HeartbeatExtension parse = HeartbeatExtension.parse(byteArrayInputStream);
            TlsProtocol.assertEmpty(byteArrayInputStream);
            return parse;
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static Vector readKeyShareClientHello(byte[] bArr) throws IOException {
        if (bArr != null) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
            if (TlsUtils.readUint16(byteArrayInputStream) == bArr.length - 2) {
                Vector vector = new Vector();
                while (byteArrayInputStream.available() > 0) {
                    vector.addElement(KeyShareEntry.parse(byteArrayInputStream));
                }
                return vector;
            }
            throw new TlsFatalAlert((short) 50);
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static int readKeyShareHelloRetryRequest(byte[] bArr) throws IOException {
        return TlsUtils.decodeUint16(bArr);
    }

    public static KeyShareEntry readKeyShareServerHello(byte[] bArr) throws IOException {
        if (bArr != null) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
            KeyShareEntry parse = KeyShareEntry.parse(byteArrayInputStream);
            TlsProtocol.assertEmpty(byteArrayInputStream);
            return parse;
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static short readMaxFragmentLengthExtension(byte[] bArr) throws IOException {
        return TlsUtils.decodeUint8(bArr);
    }

    public static Hashtable readOIDFiltersExtension(byte[] bArr) throws IOException {
        if (bArr != null) {
            if (bArr.length >= 2) {
                ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
                if (TlsUtils.readUint16(byteArrayInputStream) == bArr.length - 2) {
                    Hashtable hashtable = new Hashtable();
                    while (byteArrayInputStream.available() > 0) {
                        byte[] readOpaque8 = TlsUtils.readOpaque8(byteArrayInputStream, 1);
                        ASN1ObjectIdentifier aSN1ObjectIdentifier = ASN1ObjectIdentifier.getInstance(TlsUtils.readASN1Object(readOpaque8));
                        TlsUtils.requireDEREncoding(aSN1ObjectIdentifier, readOpaque8);
                        if (hashtable.containsKey(aSN1ObjectIdentifier)) {
                            throw new TlsFatalAlert((short) 47);
                        }
                        hashtable.put(aSN1ObjectIdentifier, TlsUtils.readOpaque16(byteArrayInputStream));
                    }
                    return hashtable;
                }
                throw new TlsFatalAlert((short) 50);
            }
            throw new TlsFatalAlert((short) 50);
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static short[] readPSKKeyExchangeModesExtension(byte[] bArr) throws IOException {
        short[] decodeUint8ArrayWithUint8Length = TlsUtils.decodeUint8ArrayWithUint8Length(bArr);
        if (decodeUint8ArrayWithUint8Length.length >= 1) {
            return decodeUint8ArrayWithUint8Length;
        }
        throw new TlsFatalAlert((short) 50);
    }

    public static int readPaddingExtension(byte[] bArr) throws IOException {
        if (bArr != null) {
            int i = 0;
            for (byte b : bArr) {
                i |= b;
            }
            if (i == 0) {
                return bArr.length;
            }
            throw new TlsFatalAlert((short) 47);
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static boolean readPostHandshakeAuthExtension(byte[] bArr) throws IOException {
        return readEmptyExtensionData(bArr);
    }

    public static OfferedPsks readPreSharedKeyClientHello(byte[] bArr) throws IOException {
        if (bArr != null) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
            OfferedPsks parse = OfferedPsks.parse(byteArrayInputStream);
            TlsProtocol.assertEmpty(byteArrayInputStream);
            return parse;
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static int readPreSharedKeyServerHello(byte[] bArr) throws IOException {
        return TlsUtils.decodeUint16(bArr);
    }

    public static int readRecordSizeLimitExtension(byte[] bArr) throws IOException {
        int decodeUint16 = TlsUtils.decodeUint16(bArr);
        if (decodeUint16 >= 64) {
            return decodeUint16;
        }
        throw new TlsFatalAlert((short) 47);
    }

    public static Vector readServerNameExtensionClient(byte[] bArr) throws IOException {
        if (bArr != null) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
            ServerNameList parse = ServerNameList.parse(byteArrayInputStream);
            TlsProtocol.assertEmpty(byteArrayInputStream);
            return parse.getServerNameList();
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static boolean readServerNameExtensionServer(byte[] bArr) throws IOException {
        return readEmptyExtensionData(bArr);
    }

    public static Vector readSignatureAlgorithmsCertExtension(byte[] bArr) throws IOException {
        return readSignatureAlgorithmsExtension(bArr);
    }

    public static Vector readSignatureAlgorithmsExtension(byte[] bArr) throws IOException {
        if (bArr != null) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
            Vector parseSupportedSignatureAlgorithms = TlsUtils.parseSupportedSignatureAlgorithms(byteArrayInputStream);
            TlsProtocol.assertEmpty(byteArrayInputStream);
            return parseSupportedSignatureAlgorithms;
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static CertificateStatusRequest readStatusRequestExtension(byte[] bArr) throws IOException {
        if (bArr != null) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
            CertificateStatusRequest parse = CertificateStatusRequest.parse(byteArrayInputStream);
            TlsProtocol.assertEmpty(byteArrayInputStream);
            return parse;
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static Vector readStatusRequestV2Extension(byte[] bArr) throws IOException {
        if (bArr != null) {
            if (bArr.length >= 3) {
                ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
                if (TlsUtils.readUint16(byteArrayInputStream) == bArr.length - 2) {
                    Vector vector = new Vector();
                    while (byteArrayInputStream.available() > 0) {
                        vector.add(CertificateStatusRequestItemV2.parse(byteArrayInputStream));
                    }
                    return vector;
                }
                throw new TlsFatalAlert((short) 50);
            }
            throw new TlsFatalAlert((short) 50);
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static int[] readSupportedGroupsExtension(byte[] bArr) throws IOException {
        if (bArr != null) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
            int readUint16 = TlsUtils.readUint16(byteArrayInputStream);
            if (readUint16 < 2 || (readUint16 & 1) != 0) {
                throw new TlsFatalAlert((short) 50);
            }
            int[] readUint16Array = TlsUtils.readUint16Array(readUint16 / 2, byteArrayInputStream);
            TlsProtocol.assertEmpty(byteArrayInputStream);
            return readUint16Array;
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static short[] readSupportedPointFormatsExtension(byte[] bArr) throws IOException {
        short[] decodeUint8ArrayWithUint8Length = TlsUtils.decodeUint8ArrayWithUint8Length(bArr);
        if (Arrays.contains(decodeUint8ArrayWithUint8Length, (short) 0)) {
            return decodeUint8ArrayWithUint8Length;
        }
        throw new TlsFatalAlert((short) 47);
    }

    public static ProtocolVersion[] readSupportedVersionsExtensionClient(byte[] bArr) throws IOException {
        if (bArr != null) {
            if (bArr.length < 3 || bArr.length > 255 || (bArr.length & 1) == 0) {
                throw new TlsFatalAlert((short) 50);
            }
            short readUint8 = TlsUtils.readUint8(bArr, 0);
            if (readUint8 == bArr.length - 1) {
                int i = readUint8 / 2;
                ProtocolVersion[] protocolVersionArr = new ProtocolVersion[i];
                for (int i2 = 0; i2 < i; i2++) {
                    protocolVersionArr[i2] = TlsUtils.readVersion(bArr, (i2 * 2) + 1);
                }
                return protocolVersionArr;
            }
            throw new TlsFatalAlert((short) 50);
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static ProtocolVersion readSupportedVersionsExtensionServer(byte[] bArr) throws IOException {
        if (bArr != null) {
            if (bArr.length == 2) {
                return TlsUtils.readVersion(bArr, 0);
            }
            throw new TlsFatalAlert((short) 50);
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static boolean readTruncatedHMacExtension(byte[] bArr) throws IOException {
        return readEmptyExtensionData(bArr);
    }

    public static Vector readTrustedCAKeysExtensionClient(byte[] bArr) throws IOException {
        if (bArr != null) {
            if (bArr.length >= 2) {
                ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
                if (TlsUtils.readUint16(byteArrayInputStream) == bArr.length - 2) {
                    Vector vector = new Vector();
                    while (byteArrayInputStream.available() > 0) {
                        vector.addElement(TrustedAuthority.parse(byteArrayInputStream));
                    }
                    return vector;
                }
                throw new TlsFatalAlert((short) 50);
            }
            throw new TlsFatalAlert((short) 50);
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static boolean readTrustedCAKeysExtensionServer(byte[] bArr) throws IOException {
        return readEmptyExtensionData(bArr);
    }
}