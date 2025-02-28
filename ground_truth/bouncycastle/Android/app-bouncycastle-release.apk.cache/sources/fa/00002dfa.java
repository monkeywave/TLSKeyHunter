package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class TlsImplUtils {
    public static byte[] calculateKeyBlock(TlsCryptoParameters tlsCryptoParameters, int i) {
        SecurityParameters securityParametersHandshake = tlsCryptoParameters.getSecurityParametersHandshake();
        return securityParametersHandshake.getMasterSecret().deriveUsingPRF(securityParametersHandshake.getPRFAlgorithm(), "key expansion", Arrays.concatenate(securityParametersHandshake.getServerRandom(), securityParametersHandshake.getClientRandom()), i).extract();
    }

    public static boolean isSSL(TlsCryptoParameters tlsCryptoParameters) {
        return tlsCryptoParameters.getServerVersion().isSSL();
    }

    public static boolean isTLSv10(ProtocolVersion protocolVersion) {
        return ProtocolVersion.TLSv10.isEqualOrEarlierVersionOf(protocolVersion.getEquivalentTLSVersion());
    }

    public static boolean isTLSv10(TlsCryptoParameters tlsCryptoParameters) {
        return isTLSv10(tlsCryptoParameters.getServerVersion());
    }

    public static boolean isTLSv11(ProtocolVersion protocolVersion) {
        return ProtocolVersion.TLSv11.isEqualOrEarlierVersionOf(protocolVersion.getEquivalentTLSVersion());
    }

    public static boolean isTLSv11(TlsCryptoParameters tlsCryptoParameters) {
        return isTLSv11(tlsCryptoParameters.getServerVersion());
    }

    public static boolean isTLSv12(ProtocolVersion protocolVersion) {
        return ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(protocolVersion.getEquivalentTLSVersion());
    }

    public static boolean isTLSv12(TlsCryptoParameters tlsCryptoParameters) {
        return isTLSv12(tlsCryptoParameters.getServerVersion());
    }

    public static boolean isTLSv13(ProtocolVersion protocolVersion) {
        return ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(protocolVersion.getEquivalentTLSVersion());
    }

    public static boolean isTLSv13(TlsCryptoParameters tlsCryptoParameters) {
        return isTLSv13(tlsCryptoParameters.getServerVersion());
    }
}