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
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public final class TlsBlockCipher implements TlsCipher {
    private final boolean acceptExtraPadding;
    private final TlsCryptoParameters cryptoParams;
    private final TlsBlockCipherImpl decryptCipher;
    private final byte[] decryptConnectionID;
    private final boolean decryptUseInnerPlaintext;
    private final TlsBlockCipherImpl encryptCipher;
    private final byte[] encryptConnectionID;
    private final boolean encryptThenMAC;
    private final boolean encryptUseInnerPlaintext;
    private final byte[] randomData;
    private final TlsSuiteMac readMac;
    private final boolean useExplicitIV;
    private final boolean useExtraPadding;
    private final TlsSuiteMac writeMac;

    public TlsBlockCipher(TlsCryptoParameters tlsCryptoParameters, TlsBlockCipherImpl tlsBlockCipherImpl, TlsBlockCipherImpl tlsBlockCipherImpl2, TlsHMAC tlsHMAC, TlsHMAC tlsHMAC2, int i) throws IOException {
        byte[] connectionIDPeer;
        byte[] connectionIDLocal;
        TlsSuiteHMac tlsSuiteHMac;
        SecurityParameters securityParametersHandshake = tlsCryptoParameters.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParametersHandshake.getNegotiatedVersion();
        if (TlsImplUtils.isTLSv13(negotiatedVersion)) {
            throw new TlsFatalAlert((short) 80);
        }
        this.decryptConnectionID = securityParametersHandshake.getConnectionIDPeer();
        this.encryptConnectionID = securityParametersHandshake.getConnectionIDLocal();
        boolean z = true;
        this.decryptUseInnerPlaintext = !Arrays.isNullOrEmpty(connectionIDPeer);
        this.encryptUseInnerPlaintext = !Arrays.isNullOrEmpty(connectionIDLocal);
        this.cryptoParams = tlsCryptoParameters;
        this.randomData = tlsCryptoParameters.getNonceGenerator().generateNonce(256);
        boolean isEncryptThenMAC = securityParametersHandshake.isEncryptThenMAC();
        this.encryptThenMAC = isEncryptThenMAC;
        boolean isTLSv11 = TlsImplUtils.isTLSv11(negotiatedVersion);
        this.useExplicitIV = isTLSv11;
        this.acceptExtraPadding = !negotiatedVersion.isSSL();
        if (!securityParametersHandshake.isExtendedPadding() || !ProtocolVersion.TLSv10.isEqualOrEarlierVersionOf(negotiatedVersion) || (!isEncryptThenMAC && securityParametersHandshake.isTruncatedHMac())) {
            z = false;
        }
        this.useExtraPadding = z;
        this.encryptCipher = tlsBlockCipherImpl;
        this.decryptCipher = tlsBlockCipherImpl2;
        if (tlsCryptoParameters.isServer()) {
            tlsBlockCipherImpl2 = tlsBlockCipherImpl;
            tlsBlockCipherImpl = tlsBlockCipherImpl2;
        }
        int macLength = (i * 2) + tlsHMAC.getMacLength() + tlsHMAC2.getMacLength();
        macLength = isTLSv11 ? macLength : macLength + tlsBlockCipherImpl.getBlockSize() + tlsBlockCipherImpl2.getBlockSize();
        byte[] calculateKeyBlock = TlsImplUtils.calculateKeyBlock(tlsCryptoParameters, macLength);
        tlsHMAC.setKey(calculateKeyBlock, 0, tlsHMAC.getMacLength());
        int macLength2 = tlsHMAC.getMacLength();
        tlsHMAC2.setKey(calculateKeyBlock, macLength2, tlsHMAC2.getMacLength());
        int macLength3 = macLength2 + tlsHMAC2.getMacLength();
        tlsBlockCipherImpl.setKey(calculateKeyBlock, macLength3, i);
        int i2 = macLength3 + i;
        tlsBlockCipherImpl2.setKey(calculateKeyBlock, i2, i);
        int i3 = i2 + i;
        int blockSize = tlsBlockCipherImpl.getBlockSize();
        int blockSize2 = tlsBlockCipherImpl2.getBlockSize();
        if (isTLSv11) {
            tlsBlockCipherImpl.init(new byte[blockSize], 0, blockSize);
            tlsBlockCipherImpl2.init(new byte[blockSize2], 0, blockSize2);
        } else {
            tlsBlockCipherImpl.init(calculateKeyBlock, i3, blockSize);
            int i4 = i3 + blockSize;
            tlsBlockCipherImpl2.init(calculateKeyBlock, i4, blockSize2);
            i3 = i4 + blockSize2;
        }
        if (i3 != macLength) {
            throw new TlsFatalAlert((short) 80);
        }
        if (tlsCryptoParameters.isServer()) {
            this.writeMac = new TlsSuiteHMac(tlsCryptoParameters, tlsHMAC2);
            tlsSuiteHMac = new TlsSuiteHMac(tlsCryptoParameters, tlsHMAC);
        } else {
            this.writeMac = new TlsSuiteHMac(tlsCryptoParameters, tlsHMAC);
            tlsSuiteHMac = new TlsSuiteHMac(tlsCryptoParameters, tlsHMAC2);
        }
        this.readMac = tlsSuiteHMac;
    }

    private int checkPaddingConstantTime(byte[] bArr, int i, int i2, int i3, int i4) {
        byte b;
        int i5;
        int i6 = i + i2;
        byte b2 = bArr[i6 - 1];
        int i7 = (b2 & UByte.MAX_VALUE) + 1;
        if (this.acceptExtraPadding) {
            i3 = 256;
        }
        if (i7 > Math.min(i3, i2 - i4)) {
            i5 = 0;
            b = 0;
            i7 = 0;
        } else {
            int i8 = i6 - i7;
            b = 0;
            while (true) {
                int i9 = i8 + 1;
                b = (byte) ((bArr[i8] ^ b2) | b);
                if (i9 >= i6) {
                    break;
                }
                i8 = i9;
            }
            i5 = i7;
            if (b != 0) {
                i7 = 0;
            }
        }
        byte[] bArr2 = this.randomData;
        while (i5 < 256) {
            b = (byte) ((bArr2[i5] ^ b2) | b);
            i5++;
        }
        bArr2[0] = (byte) (bArr2[0] ^ b);
        return i7;
    }

    private int chooseExtraPadBlocks(int i) {
        return Math.min(Integers.numberOfTrailingZeros(Pack.littleEndianToInt(this.cryptoParams.getNonceGenerator().generateNonce(4), 0)), i);
    }

    private int getCiphertextLength(int i, int i2, int i3, int i4) {
        if (this.useExplicitIV) {
            i4 += i;
        }
        int i5 = i4 + i3;
        if (this.encryptThenMAC) {
            return (i5 - (i5 % i)) + i2;
        }
        int i6 = i5 + i2;
        return i6 - (i6 % i);
    }

    private int getPlaintextLength(int i, int i2, int i3) {
        int i4;
        if (this.encryptThenMAC) {
            i4 = i3 - i2;
            i2 = i4 % i;
        } else {
            i4 = i3 - (i3 % i);
        }
        int i5 = (i4 - i2) - 1;
        return this.useExplicitIV ? i5 - i : i5;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public TlsDecodeResult decodeCiphertext(long j, short s, ProtocolVersion protocolVersion, byte[] bArr, int i, int i2) throws IOException {
        int i3;
        int i4;
        byte[] bArr2;
        short s2;
        byte b;
        int i5;
        int blockSize = this.decryptCipher.getBlockSize();
        int size = this.readMac.getSize();
        int max = this.encryptThenMAC ? blockSize + size : Math.max(blockSize, size + 1);
        if (this.useExplicitIV) {
            max += blockSize;
        }
        if (i2 >= max) {
            boolean z = this.encryptThenMAC;
            int i6 = z ? i2 - size : i2;
            if (i6 % blockSize == 0) {
                if (!z || TlsUtils.constantTimeAreEqual(size, this.readMac.calculateMac(j, s, this.decryptConnectionID, bArr, i, i2 - size), 0, bArr, (i + i2) - size)) {
                    this.decryptCipher.doFinal(bArr, i, i6, bArr, i);
                    if (this.useExplicitIV) {
                        i6 -= blockSize;
                        i3 = i + blockSize;
                    } else {
                        i3 = i;
                    }
                    int checkPaddingConstantTime = checkPaddingConstantTime(bArr, i3, i6, blockSize, this.encryptThenMAC ? 0 : size);
                    boolean z2 = checkPaddingConstantTime == 0;
                    int i7 = i6 - checkPaddingConstantTime;
                    if (this.encryptThenMAC) {
                        i4 = i3;
                        bArr2 = bArr;
                    } else {
                        i7 -= size;
                        bArr2 = bArr;
                        i4 = i3;
                        z2 |= !TlsUtils.constantTimeAreEqual(size, this.readMac.calculateMacConstantTime(j, s, this.decryptConnectionID, bArr, i5, i7, i6 - size, this.randomData), 0, bArr2, i4 + i7);
                    }
                    if (z2) {
                        throw new TlsFatalAlert((short) 20);
                    }
                    byte[] bArr3 = bArr2;
                    if (this.decryptUseInnerPlaintext) {
                        do {
                            i7--;
                            if (i7 < 0) {
                                throw new TlsFatalAlert((short) 10);
                            }
                            b = bArr3[i4 + i7];
                        } while (b == 0);
                        s2 = (short) (b & UByte.MAX_VALUE);
                    } else {
                        s2 = s;
                    }
                    return new TlsDecodeResult(bArr3, i4, i7, s2);
                }
                throw new TlsFatalAlert((short) 20);
            }
            throw new TlsFatalAlert((short) 21);
        }
        throw new TlsFatalAlert((short) 50);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public TlsEncodeResult encodePlaintext(long j, short s, ProtocolVersion protocolVersion, int i, byte[] bArr, int i2, int i3) throws IOException {
        byte[] bArr2;
        int i4;
        int i5;
        short s2;
        int i6;
        int i7;
        int blockSize = this.encryptCipher.getBlockSize();
        int size = this.writeMac.getSize();
        int i8 = i3 + (this.encryptUseInnerPlaintext ? 1 : 0);
        int i9 = blockSize - ((!this.encryptThenMAC ? i8 + size : i8) % blockSize);
        if (this.useExtraPadding) {
            i9 += chooseExtraPadBlocks((256 - i9) / blockSize) * blockSize;
        }
        int i10 = size + i8 + i9;
        boolean z = this.useExplicitIV;
        if (z) {
            i10 += blockSize;
        }
        int i11 = i + i10;
        byte[] bArr3 = new byte[i11];
        if (z) {
            System.arraycopy(this.cryptoParams.getNonceGenerator().generateNonce(blockSize), 0, bArr3, i, blockSize);
            i5 = blockSize + i;
            bArr2 = bArr;
            i4 = i2;
        } else {
            bArr2 = bArr;
            i4 = i2;
            i5 = i;
        }
        System.arraycopy(bArr2, i4, bArr3, i5, i3);
        int i12 = i3 + i5;
        if (this.encryptUseInnerPlaintext) {
            bArr3[i12] = (byte) s;
            s2 = 25;
            i12++;
        } else {
            s2 = s;
        }
        if (this.encryptThenMAC) {
            i6 = i11;
            i7 = 0;
        } else {
            i6 = i11;
            i7 = 0;
            byte[] calculateMac = this.writeMac.calculateMac(j, s2, this.encryptConnectionID, bArr3, i5, i8);
            System.arraycopy(calculateMac, 0, bArr3, i12, calculateMac.length);
            i12 += calculateMac.length;
        }
        byte b = (byte) (i9 - 1);
        int i13 = i12;
        int i14 = i7;
        while (i14 < i9) {
            bArr3[i13] = b;
            i14++;
            i13++;
        }
        int i15 = i13 - i;
        short s3 = s2;
        int i16 = i6;
        int i17 = i7;
        this.encryptCipher.doFinal(bArr3, i, i15, bArr3, i);
        if (this.encryptThenMAC) {
            byte[] calculateMac2 = this.writeMac.calculateMac(j, s3, this.encryptConnectionID, bArr3, i, i15);
            System.arraycopy(calculateMac2, i17, bArr3, i13, calculateMac2.length);
            i13 += calculateMac2.length;
        }
        if (i13 == i16) {
            return new TlsEncodeResult(bArr3, i17, i16, s3);
        }
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public int getCiphertextDecodeLimit(int i) {
        return getCiphertextLength(this.decryptCipher.getBlockSize(), this.readMac.getSize(), 256, i + (this.decryptUseInnerPlaintext ? 1 : 0));
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public int getCiphertextEncodeLimit(int i) {
        int blockSize = this.encryptCipher.getBlockSize();
        return getCiphertextLength(blockSize, this.writeMac.getSize(), this.useExtraPadding ? 256 : blockSize, i + (this.encryptUseInnerPlaintext ? 1 : 0));
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public int getPlaintextDecodeLimit(int i) {
        return getPlaintextLength(this.decryptCipher.getBlockSize(), this.readMac.getSize(), i) - (this.decryptUseInnerPlaintext ? 1 : 0);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public int getPlaintextEncodeLimit(int i) {
        return getPlaintextLength(this.encryptCipher.getBlockSize(), this.writeMac.getSize(), i) - (this.encryptUseInnerPlaintext ? 1 : 0);
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