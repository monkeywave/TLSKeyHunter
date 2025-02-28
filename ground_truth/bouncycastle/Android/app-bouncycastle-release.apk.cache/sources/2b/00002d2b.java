package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Hashtable;
import java.util.Vector;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public abstract class DTLSProtocol {
    /* JADX INFO: Access modifiers changed from: protected */
    public static void applyMaxFragmentLengthExtension(DTLSRecordLayer dTLSRecordLayer, short s) throws IOException {
        if (s >= 0) {
            if (!MaxFragmentLength.isValid(s)) {
                throw new TlsFatalAlert((short) 80);
            }
            dTLSRecordLayer.setPlaintextLimit(1 << (s + 8));
        }
    }

    protected static short evaluateMaxFragmentLengthExtension(boolean z, Hashtable hashtable, Hashtable hashtable2, short s) throws IOException {
        if (z) {
            hashtable = null;
        }
        return TlsUtils.processMaxFragmentLengthExtension(hashtable, hashtable2, s);
    }

    protected static byte[] generateCertificate(TlsContext tlsContext, Certificate certificate, OutputStream outputStream) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        certificate.encode(tlsContext, byteArrayOutputStream, outputStream);
        return byteArrayOutputStream.toByteArray();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static byte[] generateSupplementalData(Vector vector) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsProtocol.writeSupplementalData(byteArrayOutputStream, vector);
        return byteArrayOutputStream.toByteArray();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static void sendCertificateMessage(TlsContext tlsContext, DTLSReliableHandshake dTLSReliableHandshake, Certificate certificate, OutputStream outputStream) throws IOException {
        SecurityParameters securityParametersHandshake = tlsContext.getSecurityParametersHandshake();
        if (securityParametersHandshake.getLocalCertificate() != null) {
            throw new TlsFatalAlert((short) 80);
        }
        if (certificate == null) {
            certificate = Certificate.EMPTY_CHAIN;
        }
        dTLSReliableHandshake.sendMessage((short) 11, generateCertificate(tlsContext, certificate, outputStream));
        securityParametersHandshake.localCertificate = certificate;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static int validateSelectedCipherSuite(int i, short s) throws IOException {
        int encryptionAlgorithmType;
        int encryptionAlgorithm = TlsUtils.getEncryptionAlgorithm(i);
        if (encryptionAlgorithm == 0 || ((encryptionAlgorithmType = TlsUtils.getEncryptionAlgorithmType(encryptionAlgorithm)) >= 0 && encryptionAlgorithmType != 0)) {
            return i;
        }
        throw new TlsFatalAlert(s);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void processFinished(byte[] bArr, byte[] bArr2) throws IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        byte[] readFully = TlsUtils.readFully(bArr2.length, byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        if (!Arrays.constantTimeAreEqual(bArr2, readFully)) {
            throw new TlsFatalAlert((short) 40);
        }
    }
}