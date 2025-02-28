package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.tls.crypto.TlsMAC;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public final class TlsSuiteHMac implements TlsSuiteMac {
    private static final long SEQUENCE_NUMBER_PLACEHOLDER = -1;
    private final TlsCryptoParameters cryptoParams;
    private final int digestBlockSize;
    private final int digestOverhead;
    private final TlsHMAC mac;
    private final int macSize;

    public TlsSuiteHMac(TlsCryptoParameters tlsCryptoParameters, TlsHMAC tlsHMAC) {
        this.cryptoParams = tlsCryptoParameters;
        this.mac = tlsHMAC;
        this.macSize = getMacSize(tlsCryptoParameters, tlsHMAC);
        int internalBlockSize = tlsHMAC.getInternalBlockSize();
        this.digestBlockSize = internalBlockSize;
        if (TlsImplUtils.isSSL(tlsCryptoParameters) && tlsHMAC.getMacLength() == 20) {
            this.digestOverhead = 4;
        } else {
            this.digestOverhead = internalBlockSize / 8;
        }
    }

    private int getDigestBlockCount(int i) {
        return (i + this.digestOverhead) / this.digestBlockSize;
    }

    private int getHeaderLength(byte[] bArr) {
        if (TlsImplUtils.isSSL(this.cryptoParams)) {
            return 11;
        }
        if (Arrays.isNullOrEmpty(bArr)) {
            return 13;
        }
        return bArr.length + 23;
    }

    private static int getMacSize(TlsCryptoParameters tlsCryptoParameters, TlsMAC tlsMAC) {
        int macLength = tlsMAC.getMacLength();
        return tlsCryptoParameters.getSecurityParametersHandshake().isTruncatedHMac() ? Math.min(macLength, 10) : macLength;
    }

    private byte[] truncate(byte[] bArr) {
        int length = bArr.length;
        int i = this.macSize;
        return length <= i ? bArr : Arrays.copyOf(bArr, i);
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsSuiteMac
    public byte[] calculateMac(long j, short s, byte[] bArr, byte[] bArr2, int i, int i2) {
        ProtocolVersion serverVersion = this.cryptoParams.getServerVersion();
        if (Arrays.isNullOrEmpty(bArr)) {
            byte[] bArr3 = new byte[13];
            TlsUtils.writeUint64(j, bArr3, 0);
            TlsUtils.writeUint8(s, bArr3, 8);
            TlsUtils.writeVersion(serverVersion, bArr3, 9);
            TlsUtils.writeUint16(i2, bArr3, 11);
            this.mac.update(bArr3, 0, 13);
        } else {
            int length = bArr.length;
            int i3 = length + 23;
            byte[] bArr4 = new byte[i3];
            TlsUtils.writeUint64(-1L, bArr4, 0);
            TlsUtils.writeUint8((short) 25, bArr4, 8);
            TlsUtils.writeUint8(length, bArr4, 9);
            TlsUtils.writeUint8((short) 25, bArr4, 10);
            TlsUtils.writeVersion(serverVersion, bArr4, 11);
            TlsUtils.writeUint64(j, bArr4, 13);
            System.arraycopy(bArr, 0, bArr4, 21, length);
            TlsUtils.writeUint16(i2, bArr4, length + 21);
            this.mac.update(bArr4, 0, i3);
        }
        this.mac.update(bArr2, i, i2);
        return truncate(this.mac.calculateMAC());
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsSuiteMac
    public byte[] calculateMacConstantTime(long j, short s, byte[] bArr, byte[] bArr2, int i, int i2, int i3, byte[] bArr3) {
        byte[] calculateMac = calculateMac(j, s, bArr, bArr2, i, i2);
        int headerLength = getHeaderLength(bArr);
        int digestBlockCount = getDigestBlockCount(i3 + headerLength) - getDigestBlockCount(headerLength + i2);
        while (true) {
            digestBlockCount--;
            if (digestBlockCount < 0) {
                this.mac.update(bArr3, 0, 1);
                this.mac.reset();
                return calculateMac;
            }
            this.mac.update(bArr3, 0, this.digestBlockSize);
        }
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsSuiteMac
    public int getSize() {
        return this.macSize;
    }
}