package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;
import kotlin.UByte;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsDecodeResult;
import org.bouncycastle.tls.crypto.TlsEncodeResult;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public final class TlsNullCipher implements TlsCipher {
    private final byte[] decryptConnectionID;
    private final boolean decryptUseInnerPlaintext;
    private final byte[] encryptConnectionID;
    private final boolean encryptUseInnerPlaintext;
    private final TlsSuiteHMac readMac;
    private final TlsSuiteHMac writeMac;

    public TlsNullCipher(TlsCryptoParameters tlsCryptoParameters, TlsHMAC tlsHMAC, TlsHMAC tlsHMAC2) throws IOException {
        SecurityParameters securityParametersHandshake = tlsCryptoParameters.getSecurityParametersHandshake();
        if (TlsImplUtils.isTLSv13(securityParametersHandshake.getNegotiatedVersion())) {
            throw new TlsFatalAlert((short) 80);
        }
        byte[] connectionIDPeer = securityParametersHandshake.getConnectionIDPeer();
        this.decryptConnectionID = connectionIDPeer;
        byte[] connectionIDLocal = securityParametersHandshake.getConnectionIDLocal();
        this.encryptConnectionID = connectionIDLocal;
        this.decryptUseInnerPlaintext = !Arrays.isNullOrEmpty(connectionIDPeer);
        this.encryptUseInnerPlaintext = !Arrays.isNullOrEmpty(connectionIDLocal);
        int macLength = tlsHMAC.getMacLength() + tlsHMAC2.getMacLength();
        byte[] calculateKeyBlock = TlsImplUtils.calculateKeyBlock(tlsCryptoParameters, macLength);
        tlsHMAC.setKey(calculateKeyBlock, 0, tlsHMAC.getMacLength());
        int macLength2 = tlsHMAC.getMacLength();
        tlsHMAC2.setKey(calculateKeyBlock, macLength2, tlsHMAC2.getMacLength());
        if (macLength2 + tlsHMAC2.getMacLength() != macLength) {
            throw new TlsFatalAlert((short) 80);
        }
        if (tlsCryptoParameters.isServer()) {
            this.writeMac = new TlsSuiteHMac(tlsCryptoParameters, tlsHMAC2);
            this.readMac = new TlsSuiteHMac(tlsCryptoParameters, tlsHMAC);
            return;
        }
        this.writeMac = new TlsSuiteHMac(tlsCryptoParameters, tlsHMAC);
        this.readMac = new TlsSuiteHMac(tlsCryptoParameters, tlsHMAC2);
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [boolean] */
    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public TlsDecodeResult decodeCiphertext(long j, short s, ProtocolVersion protocolVersion, byte[] bArr, int i, int i2) throws IOException {
        byte b;
        int size = this.readMac.getSize();
        int i3 = i2 - size;
        if (i3 >= this.decryptUseInnerPlaintext) {
            if (TlsUtils.constantTimeAreEqual(size, this.readMac.calculateMac(j, s, this.decryptConnectionID, bArr, i, i3), 0, bArr, i + i3)) {
                if (this.decryptUseInnerPlaintext) {
                    do {
                        i3--;
                        if (i3 < 0) {
                            throw new TlsFatalAlert((short) 10);
                        }
                        b = bArr[i + i3];
                    } while (b == 0);
                    s = (short) (b & UByte.MAX_VALUE);
                }
                return new TlsDecodeResult(bArr, i, i3, s);
            }
            throw new TlsFatalAlert((short) 20);
        }
        throw new TlsFatalAlert((short) 50);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public TlsEncodeResult encodePlaintext(long j, short s, ProtocolVersion protocolVersion, int i, byte[] bArr, int i2, int i3) throws IOException {
        short s2;
        int size = this.writeMac.getSize();
        int i4 = i3 + (this.encryptUseInnerPlaintext ? 1 : 0);
        int i5 = i + i4;
        int i6 = i5 + size;
        byte[] bArr2 = new byte[i6];
        System.arraycopy(bArr, i2, bArr2, i, i3);
        if (this.encryptUseInnerPlaintext) {
            bArr2[i3 + i] = (byte) s;
            s2 = 25;
        } else {
            s2 = s;
        }
        byte[] calculateMac = this.writeMac.calculateMac(j, s2, this.encryptConnectionID, bArr2, i, i4);
        System.arraycopy(calculateMac, 0, bArr2, i5, calculateMac.length);
        return new TlsEncodeResult(bArr2, 0, i6, s2);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public int getCiphertextDecodeLimit(int i) {
        return i + (this.decryptUseInnerPlaintext ? 1 : 0) + this.readMac.getSize();
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public int getCiphertextEncodeLimit(int i) {
        return i + (this.encryptUseInnerPlaintext ? 1 : 0) + this.writeMac.getSize();
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public int getPlaintextDecodeLimit(int i) {
        return (i - this.readMac.getSize()) - (this.decryptUseInnerPlaintext ? 1 : 0);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public int getPlaintextEncodeLimit(int i) {
        return (i - this.writeMac.getSize()) - (this.encryptUseInnerPlaintext ? 1 : 0);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public void rekeyDecoder() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public void rekeyEncoder() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public boolean usesOpaqueRecordTypeDecode() {
        return this.decryptUseInnerPlaintext;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public boolean usesOpaqueRecordTypeEncode() {
        return this.encryptUseInnerPlaintext;
    }
}