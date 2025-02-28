package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.tls.crypto.TlsMACOutputStream;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class DTLSVerifier {
    private final TlsCrypto crypto;
    private final byte[] macKey;

    public DTLSVerifier(TlsCrypto tlsCrypto) {
        this.crypto = tlsCrypto;
        byte[] bArr = new byte[32];
        this.macKey = bArr;
        tlsCrypto.getSecureRandom().nextBytes(bArr);
    }

    public DTLSRequest verifyRequest(byte[] bArr, byte[] bArr2, int i, int i2, DatagramSender datagramSender) {
        int receiveClientHelloRecord;
        int i3;
        int i4;
        ByteArrayInputStream receiveClientHelloMessage;
        ByteArrayOutputStream byteArrayOutputStream;
        ClientHello parse;
        try {
            receiveClientHelloRecord = DTLSRecordLayer.receiveClientHelloRecord(bArr2, i, i2);
        } catch (IOException unused) {
        }
        if (receiveClientHelloRecord >= 0 && receiveClientHelloRecord - 12 >= 39 && (receiveClientHelloMessage = DTLSReliableHandshake.receiveClientHelloMessage(bArr2, (i4 = i + 13), receiveClientHelloRecord)) != null && (parse = ClientHello.parse(receiveClientHelloMessage, (byteArrayOutputStream = new ByteArrayOutputStream(i3)))) != null) {
            long readUint48 = TlsUtils.readUint48(bArr2, i + 5);
            byte[] cookie = parse.getCookie();
            TlsHMAC createHMAC = this.crypto.createHMAC(3);
            byte[] bArr3 = this.macKey;
            createHMAC.setKey(bArr3, 0, bArr3.length);
            createHMAC.update(bArr, 0, bArr.length);
            byteArrayOutputStream.writeTo(new TlsMACOutputStream(createHMAC));
            byte[] calculateMAC = createHMAC.calculateMAC();
            if (Arrays.constantTimeAreEqual(calculateMAC, cookie)) {
                return new DTLSRequest(readUint48, TlsUtils.copyOfRangeExact(bArr2, i4, receiveClientHelloRecord + i4), parse);
            }
            DTLSReliableHandshake.sendHelloVerifyRequest(datagramSender, readUint48, calculateMAC);
            return null;
        }
        return null;
    }
}