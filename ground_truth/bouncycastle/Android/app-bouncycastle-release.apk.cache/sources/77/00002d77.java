package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.p019io.Streams;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class SSL3Utils {
    private static final byte[] SSL_CLIENT = {67, 76, 78, 84};
    private static final byte[] SSL_SERVER = {83, 82, 86, 82};
    private static final byte IPAD_BYTE = 54;
    private static final byte[] IPAD = genPad(IPAD_BYTE, 48);
    private static final byte OPAD_BYTE = 92;
    private static final byte[] OPAD = genPad(OPAD_BYTE, 48);

    SSL3Utils() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] calculateVerifyData(TlsHandshakeHash tlsHandshakeHash, boolean z) {
        TlsHash forkPRFHash = tlsHandshakeHash.forkPRFHash();
        byte[] bArr = z ? SSL_SERVER : SSL_CLIENT;
        forkPRFHash.update(bArr, 0, bArr.length);
        return forkPRFHash.calculateHash();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void completeCombinedHash(TlsContext tlsContext, TlsHash tlsHash, TlsHash tlsHash2) {
        byte[] extract = tlsContext.getCrypto().adoptSecret(tlsContext.getSecurityParametersHandshake().getMasterSecret()).extract();
        completeHash(extract, tlsHash, 48);
        completeHash(extract, tlsHash2, 40);
    }

    private static void completeHash(byte[] bArr, TlsHash tlsHash, int i) {
        tlsHash.update(bArr, 0, bArr.length);
        tlsHash.update(IPAD, 0, i);
        byte[] calculateHash = tlsHash.calculateHash();
        tlsHash.update(bArr, 0, bArr.length);
        tlsHash.update(OPAD, 0, i);
        tlsHash.update(calculateHash, 0, calculateHash.length);
    }

    private static byte[] genPad(byte b, int i) {
        byte[] bArr = new byte[i];
        Arrays.fill(bArr, b);
        return bArr;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] readEncryptedPMS(InputStream inputStream) throws IOException {
        return Streams.readAll(inputStream);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void writeEncryptedPMS(byte[] bArr, OutputStream outputStream) throws IOException {
        outputStream.write(bArr);
    }
}