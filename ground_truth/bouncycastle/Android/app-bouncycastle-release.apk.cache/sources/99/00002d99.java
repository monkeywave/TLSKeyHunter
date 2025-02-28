package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class TlsECCUtils {
    public static void checkPointEncoding(int i, byte[] bArr) throws IOException {
        if (TlsUtils.isNullOrEmpty(bArr)) {
            throw new TlsFatalAlert((short) 47);
        }
        if (i != 29 && i != 30 && bArr[0] != 4) {
            throw new TlsFatalAlert((short) 47);
        }
    }

    public static TlsECConfig createNamedECConfig(TlsContext tlsContext, int i) throws IOException {
        if (NamedGroup.getCurveBits(i) >= 1) {
            return new TlsECConfig(i);
        }
        throw new TlsFatalAlert((short) 80);
    }

    public static int getMinimumCurveBits(int i) {
        return isECCCipherSuite(i) ? 1 : 0;
    }

    public static boolean isECCCipherSuite(int i) {
        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(i);
        if (keyExchangeAlgorithm == 24 || keyExchangeAlgorithm == 26) {
            return true;
        }
        switch (keyExchangeAlgorithm) {
            case 16:
            case 17:
            case 18:
            case 19:
            case 20:
                return true;
            default:
                return false;
        }
    }

    public static TlsECConfig receiveECDHConfig(TlsContext tlsContext, InputStream inputStream) throws IOException {
        int[] clientSupportedGroups;
        if (TlsUtils.readUint8(inputStream) == 3) {
            int readUint16 = TlsUtils.readUint16(inputStream);
            if (NamedGroup.refersToAnECDHCurve(readUint16) && ((clientSupportedGroups = tlsContext.getSecurityParametersHandshake().getClientSupportedGroups()) == null || Arrays.contains(clientSupportedGroups, readUint16))) {
                return new TlsECConfig(readUint16);
            }
            throw new TlsFatalAlert((short) 47);
        }
        throw new TlsFatalAlert((short) 40);
    }

    public static void writeECConfig(TlsECConfig tlsECConfig, OutputStream outputStream) throws IOException {
        writeNamedECParameters(tlsECConfig.getNamedGroup(), outputStream);
    }

    public static void writeNamedECParameters(int i, OutputStream outputStream) throws IOException {
        if (!NamedGroup.refersToASpecificCurve(i)) {
            throw new TlsFatalAlert((short) 80);
        }
        TlsUtils.writeUint8((short) 3, outputStream);
        TlsUtils.checkUint16(i);
        TlsUtils.writeUint16(i, outputStream);
    }
}