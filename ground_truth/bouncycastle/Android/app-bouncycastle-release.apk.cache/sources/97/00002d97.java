package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import org.bouncycastle.tls.crypto.DHGroup;
import org.bouncycastle.tls.crypto.DHStandardGroups;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/* loaded from: classes2.dex */
public class TlsDHUtils {
    public static TlsDHConfig createNamedDHConfig(TlsContext tlsContext, int i) {
        if (i < 0 || NamedGroup.getFiniteFieldBits(i) < 1) {
            return null;
        }
        return new TlsDHConfig(i, TlsUtils.isTLSv13(tlsContext));
    }

    public static DHGroup getDHGroup(TlsDHConfig tlsDHConfig) {
        int namedGroup = tlsDHConfig.getNamedGroup();
        return namedGroup >= 0 ? getNamedDHGroup(namedGroup) : tlsDHConfig.getExplicitGroup();
    }

    public static int getMinimumFiniteFieldBits(int i) {
        return isDHCipherSuite(i) ? 1 : 0;
    }

    public static DHGroup getNamedDHGroup(int i) {
        switch (i) {
            case 256:
                return DHStandardGroups.rfc7919_ffdhe2048;
            case 257:
                return DHStandardGroups.rfc7919_ffdhe3072;
            case NamedGroup.ffdhe4096 /* 258 */:
                return DHStandardGroups.rfc7919_ffdhe4096;
            case NamedGroup.ffdhe6144 /* 259 */:
                return DHStandardGroups.rfc7919_ffdhe6144;
            case NamedGroup.ffdhe8192 /* 260 */:
                return DHStandardGroups.rfc7919_ffdhe8192;
            default:
                return null;
        }
    }

    public static int getNamedGroupForDHParameters(BigInteger bigInteger, BigInteger bigInteger2) {
        int[] iArr = {256, 257, NamedGroup.ffdhe4096, NamedGroup.ffdhe6144, NamedGroup.ffdhe8192};
        for (int i = 0; i < 5; i++) {
            int i2 = iArr[i];
            DHGroup namedDHGroup = getNamedDHGroup(i2);
            if (namedDHGroup != null && namedDHGroup.getP().equals(bigInteger) && namedDHGroup.getG().equals(bigInteger2)) {
                return i2;
            }
        }
        return -1;
    }

    public static DHGroup getStandardGroupForDHParameters(BigInteger bigInteger, BigInteger bigInteger2) {
        DHGroup[] dHGroupArr = {DHStandardGroups.rfc7919_ffdhe2048, DHStandardGroups.rfc7919_ffdhe3072, DHStandardGroups.rfc7919_ffdhe4096, DHStandardGroups.rfc7919_ffdhe6144, DHStandardGroups.rfc7919_ffdhe8192, DHStandardGroups.rfc3526_1536, DHStandardGroups.rfc3526_2048, DHStandardGroups.rfc3526_3072, DHStandardGroups.rfc3526_4096, DHStandardGroups.rfc3526_6144, DHStandardGroups.rfc3526_8192, DHStandardGroups.rfc5996_768, DHStandardGroups.rfc5996_1024};
        for (int i = 0; i < 13; i++) {
            DHGroup dHGroup = dHGroupArr[i];
            if (dHGroup != null && dHGroup.getP().equals(bigInteger) && dHGroup.getG().equals(bigInteger2)) {
                return dHGroup;
            }
        }
        return null;
    }

    public static boolean isDHCipherSuite(int i) {
        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(i);
        return keyExchangeAlgorithm == 3 || keyExchangeAlgorithm == 5 || keyExchangeAlgorithm == 7 || keyExchangeAlgorithm == 9 || keyExchangeAlgorithm == 11 || keyExchangeAlgorithm == 14;
    }

    public static BigInteger readDHParameter(InputStream inputStream) throws IOException {
        return new BigInteger(1, TlsUtils.readOpaque16(inputStream, 1));
    }

    public static TlsDHConfig receiveDHConfig(TlsContext tlsContext, TlsDHGroupVerifier tlsDHGroupVerifier, InputStream inputStream) throws IOException {
        BigInteger readDHParameter = readDHParameter(inputStream);
        BigInteger readDHParameter2 = readDHParameter(inputStream);
        int namedGroupForDHParameters = getNamedGroupForDHParameters(readDHParameter, readDHParameter2);
        if (namedGroupForDHParameters >= 0) {
            int[] clientSupportedGroups = tlsContext.getSecurityParametersHandshake().getClientSupportedGroups();
            if (clientSupportedGroups == null || Arrays.contains(clientSupportedGroups, namedGroupForDHParameters)) {
                return new TlsDHConfig(namedGroupForDHParameters, false);
            }
            throw new TlsFatalAlert((short) 47);
        }
        DHGroup standardGroupForDHParameters = getStandardGroupForDHParameters(readDHParameter, readDHParameter2);
        if (standardGroupForDHParameters == null) {
            standardGroupForDHParameters = new DHGroup(readDHParameter, null, readDHParameter2, 0);
        }
        if (tlsDHGroupVerifier.accept(standardGroupForDHParameters)) {
            return new TlsDHConfig(standardGroupForDHParameters);
        }
        throw new TlsFatalAlert((short) 71);
    }

    public static void writeDHConfig(TlsDHConfig tlsDHConfig, OutputStream outputStream) throws IOException {
        DHGroup dHGroup = getDHGroup(tlsDHConfig);
        writeDHParameter(dHGroup.getP(), outputStream);
        writeDHParameter(dHGroup.getG(), outputStream);
    }

    public static void writeDHParameter(BigInteger bigInteger, OutputStream outputStream) throws IOException {
        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(bigInteger), outputStream);
    }
}