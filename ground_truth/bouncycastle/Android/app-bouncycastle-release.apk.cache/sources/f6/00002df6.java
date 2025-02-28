package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;
import kotlin.UByte;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsDecodeResult;
import org.bouncycastle.tls.crypto.TlsEncodeResult;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public final class TlsAEADCipher implements TlsCipher {
    public static final int AEAD_CCM = 1;
    public static final int AEAD_CHACHA20_POLY1305 = 2;
    public static final int AEAD_GCM = 3;
    private static final int NONCE_RFC5288 = 1;
    private static final int NONCE_RFC7905 = 2;
    private static final long SEQUENCE_NUMBER_PLACEHOLDER = -1;
    private final TlsCryptoParameters cryptoParams;
    private final TlsAEADCipherImpl decryptCipher;
    private final byte[] decryptConnectionID;
    private final byte[] decryptNonce;
    private final boolean decryptUseInnerPlaintext;
    private final TlsAEADCipherImpl encryptCipher;
    private final byte[] encryptConnectionID;
    private final byte[] encryptNonce;
    private final boolean encryptUseInnerPlaintext;
    private final int fixed_iv_length;
    private final boolean isTLSv13;
    private final int keySize;
    private final int macSize;
    private final int nonceMode;
    private final int record_iv_length;

    public TlsAEADCipher(TlsCryptoParameters tlsCryptoParameters, TlsAEADCipherImpl tlsAEADCipherImpl, TlsAEADCipherImpl tlsAEADCipherImpl2, int i, int i2, int i3) throws IOException {
        int i4;
        SecurityParameters securityParametersHandshake = tlsCryptoParameters.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParametersHandshake.getNegotiatedVersion();
        if (!TlsImplUtils.isTLSv12(negotiatedVersion)) {
            throw new TlsFatalAlert((short) 80);
        }
        boolean isTLSv13 = TlsImplUtils.isTLSv13(negotiatedVersion);
        this.isTLSv13 = isTLSv13;
        int nonceMode = getNonceMode(isTLSv13, i3);
        this.nonceMode = nonceMode;
        byte[] connectionIDPeer = securityParametersHandshake.getConnectionIDPeer();
        this.decryptConnectionID = connectionIDPeer;
        byte[] connectionIDLocal = securityParametersHandshake.getConnectionIDLocal();
        this.encryptConnectionID = connectionIDLocal;
        this.decryptUseInnerPlaintext = isTLSv13 || !Arrays.isNullOrEmpty(connectionIDPeer);
        this.encryptUseInnerPlaintext = isTLSv13 || !Arrays.isNullOrEmpty(connectionIDLocal);
        if (nonceMode == 1) {
            this.fixed_iv_length = 4;
            this.record_iv_length = 8;
        } else if (nonceMode != 2) {
            throw new TlsFatalAlert((short) 80);
        } else {
            this.fixed_iv_length = 12;
            this.record_iv_length = 0;
        }
        this.cryptoParams = tlsCryptoParameters;
        this.keySize = i;
        this.macSize = i2;
        this.decryptCipher = tlsAEADCipherImpl2;
        this.encryptCipher = tlsAEADCipherImpl;
        int i5 = this.fixed_iv_length;
        byte[] bArr = new byte[i5];
        this.decryptNonce = bArr;
        byte[] bArr2 = new byte[i5];
        this.encryptNonce = bArr2;
        boolean isServer = tlsCryptoParameters.isServer();
        if (isTLSv13) {
            rekeyCipher(securityParametersHandshake, tlsAEADCipherImpl2, bArr, !isServer);
            rekeyCipher(securityParametersHandshake, tlsAEADCipherImpl, bArr2, isServer);
            return;
        }
        int i6 = (i * 2) + (this.fixed_iv_length * 2);
        byte[] calculateKeyBlock = TlsImplUtils.calculateKeyBlock(tlsCryptoParameters, i6);
        if (isServer) {
            tlsAEADCipherImpl2.setKey(calculateKeyBlock, 0, i);
            tlsAEADCipherImpl.setKey(calculateKeyBlock, i, i);
            int i7 = i + i;
            System.arraycopy(calculateKeyBlock, i7, bArr, 0, this.fixed_iv_length);
            int i8 = this.fixed_iv_length;
            i4 = i7 + i8;
            System.arraycopy(calculateKeyBlock, i4, bArr2, 0, i8);
        } else {
            tlsAEADCipherImpl.setKey(calculateKeyBlock, 0, i);
            tlsAEADCipherImpl2.setKey(calculateKeyBlock, i, i);
            int i9 = i + i;
            System.arraycopy(calculateKeyBlock, i9, bArr2, 0, this.fixed_iv_length);
            int i10 = this.fixed_iv_length;
            i4 = i9 + i10;
            System.arraycopy(calculateKeyBlock, i4, bArr, 0, i10);
        }
        if (i6 != i4 + this.fixed_iv_length) {
            throw new TlsFatalAlert((short) 80);
        }
    }

    private byte[] getAdditionalData(long j, short s, ProtocolVersion protocolVersion, int i, int i2, byte[] bArr) throws IOException {
        if (!Arrays.isNullOrEmpty(bArr)) {
            int length = bArr.length;
            byte[] bArr2 = new byte[length + 23];
            TlsUtils.writeUint64(-1L, bArr2, 0);
            TlsUtils.writeUint8((short) 25, bArr2, 8);
            TlsUtils.writeUint8(length, bArr2, 9);
            TlsUtils.writeUint8((short) 25, bArr2, 10);
            TlsUtils.writeVersion(protocolVersion, bArr2, 11);
            TlsUtils.writeUint64(j, bArr2, 13);
            System.arraycopy(bArr, 0, bArr2, 21, length);
            TlsUtils.writeUint16(i2, bArr2, length + 21);
            return bArr2;
        } else if (this.isTLSv13) {
            byte[] bArr3 = new byte[5];
            TlsUtils.writeUint8(s, bArr3, 0);
            TlsUtils.writeVersion(protocolVersion, bArr3, 1);
            TlsUtils.writeUint16(i, bArr3, 3);
            return bArr3;
        } else {
            byte[] bArr4 = new byte[13];
            TlsUtils.writeUint64(j, bArr4, 0);
            TlsUtils.writeUint8(s, bArr4, 8);
            TlsUtils.writeVersion(protocolVersion, bArr4, 9);
            TlsUtils.writeUint16(i2, bArr4, 11);
            return bArr4;
        }
    }

    private static int getNonceMode(boolean z, int i) throws IOException {
        if (i != 1) {
            if (i == 2) {
                return 2;
            }
            if (i != 3) {
                throw new TlsFatalAlert((short) 80);
            }
        }
        return z ? 2 : 1;
    }

    private void rekeyCipher(SecurityParameters securityParameters, TlsAEADCipherImpl tlsAEADCipherImpl, byte[] bArr, boolean z) throws IOException {
        if (!this.isTLSv13) {
            throw new TlsFatalAlert((short) 80);
        }
        TlsSecret trafficSecretServer = z ? securityParameters.getTrafficSecretServer() : securityParameters.getTrafficSecretClient();
        if (trafficSecretServer == null) {
            throw new TlsFatalAlert((short) 80);
        }
        setup13Cipher(tlsAEADCipherImpl, bArr, trafficSecretServer, securityParameters.getPRFCryptoHashAlgorithm());
    }

    private void setup13Cipher(TlsAEADCipherImpl tlsAEADCipherImpl, byte[] bArr, TlsSecret tlsSecret, int i) throws IOException {
        byte[] extract = TlsCryptoUtils.hkdfExpandLabel(tlsSecret, i, "key", TlsUtils.EMPTY_BYTES, this.keySize).extract();
        byte[] extract2 = TlsCryptoUtils.hkdfExpandLabel(tlsSecret, i, "iv", TlsUtils.EMPTY_BYTES, this.fixed_iv_length).extract();
        tlsAEADCipherImpl.setKey(extract, 0, this.keySize);
        System.arraycopy(extract2, 0, bArr, 0, this.fixed_iv_length);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public TlsDecodeResult decodeCiphertext(long j, short s, ProtocolVersion protocolVersion, byte[] bArr, int i, int i2) throws IOException {
        short s2;
        byte b;
        if (getPlaintextDecodeLimit(i2) >= 0) {
            byte[] bArr2 = this.decryptNonce;
            int length = bArr2.length + this.record_iv_length;
            byte[] bArr3 = new byte[length];
            int i3 = this.nonceMode;
            int i4 = 0;
            if (i3 == 1) {
                System.arraycopy(bArr2, 0, bArr3, 0, bArr2.length);
                int i5 = this.record_iv_length;
                System.arraycopy(bArr, i, bArr3, length - i5, i5);
            } else if (i3 != 2) {
                throw new TlsFatalAlert((short) 80);
            } else {
                TlsUtils.writeUint64(j, bArr3, length - 8);
                while (true) {
                    byte[] bArr4 = this.decryptNonce;
                    if (i4 >= bArr4.length) {
                        break;
                    }
                    bArr3[i4] = (byte) (bArr4[i4] ^ bArr3[i4]);
                    i4++;
                }
            }
            this.decryptCipher.init(bArr3, this.macSize);
            int i6 = this.record_iv_length;
            int i7 = i + i6;
            int i8 = i2 - i6;
            int outputSize = this.decryptCipher.getOutputSize(i8);
            try {
                if (this.decryptCipher.doFinal(getAdditionalData(j, s, protocolVersion, i2, outputSize, this.decryptConnectionID), bArr, i7, i8, bArr, i7) == outputSize) {
                    if (this.decryptUseInnerPlaintext) {
                        do {
                            outputSize--;
                            if (outputSize < 0) {
                                throw new TlsFatalAlert((short) 10);
                            }
                            b = bArr[i7 + outputSize];
                        } while (b == 0);
                        s2 = (short) (b & UByte.MAX_VALUE);
                    } else {
                        s2 = s;
                    }
                    return new TlsDecodeResult(bArr, i7, outputSize, s2);
                }
                throw new TlsFatalAlert((short) 80);
            } catch (RuntimeException e) {
                throw new TlsFatalAlert((short) 20, (Throwable) e);
            }
        }
        throw new TlsFatalAlert((short) 50);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public TlsEncodeResult encodePlaintext(long j, short s, ProtocolVersion protocolVersion, int i, byte[] bArr, int i2, int i3) throws IOException {
        short s2;
        int i4 = i;
        byte[] bArr2 = this.encryptNonce;
        int length = bArr2.length + this.record_iv_length;
        byte[] bArr3 = new byte[length];
        int i5 = this.nonceMode;
        if (i5 == 1) {
            System.arraycopy(bArr2, 0, bArr3, 0, bArr2.length);
            TlsUtils.writeUint64(j, bArr3, this.encryptNonce.length);
        } else if (i5 != 2) {
            throw new TlsFatalAlert((short) 80);
        } else {
            TlsUtils.writeUint64(j, bArr3, length - 8);
            int i6 = 0;
            while (true) {
                byte[] bArr4 = this.encryptNonce;
                if (i6 >= bArr4.length) {
                    break;
                }
                bArr3[i6] = (byte) (bArr4[i6] ^ bArr3[i6]);
                i6++;
            }
        }
        int i7 = i3 + (this.encryptUseInnerPlaintext ? 1 : 0);
        this.encryptCipher.init(bArr3, this.macSize);
        int outputSize = this.encryptCipher.getOutputSize(i7);
        int i8 = this.record_iv_length;
        int i9 = i8 + outputSize;
        int i10 = i4 + i9;
        byte[] bArr5 = new byte[i10];
        if (i8 != 0) {
            System.arraycopy(bArr3, length - i8, bArr5, i4, i8);
            i4 += this.record_iv_length;
        }
        if (this.encryptUseInnerPlaintext) {
            s2 = this.isTLSv13 ? (short) 23 : (short) 25;
        } else {
            s2 = s;
        }
        short s3 = s2;
        byte[] additionalData = getAdditionalData(j, s2, protocolVersion, i9, i7, this.encryptConnectionID);
        try {
            System.arraycopy(bArr, i2, bArr5, i4, i3);
            if (this.encryptUseInnerPlaintext) {
                bArr5[i4 + i3] = (byte) s;
            }
            if (i4 + this.encryptCipher.doFinal(additionalData, bArr5, i4, i7, bArr5, i4) == i10) {
                return new TlsEncodeResult(bArr5, 0, i10, s3);
            }
            throw new TlsFatalAlert((short) 80);
        } catch (RuntimeException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public int getCiphertextDecodeLimit(int i) {
        return i + (this.decryptUseInnerPlaintext ? 1 : 0) + this.macSize + this.record_iv_length;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public int getCiphertextEncodeLimit(int i) {
        return i + (this.encryptUseInnerPlaintext ? 1 : 0) + this.macSize + this.record_iv_length;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public int getPlaintextDecodeLimit(int i) {
        return ((i - this.macSize) - this.record_iv_length) - (this.decryptUseInnerPlaintext ? 1 : 0);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public int getPlaintextEncodeLimit(int i) {
        return ((i - this.macSize) - this.record_iv_length) - (this.encryptUseInnerPlaintext ? 1 : 0);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public void rekeyDecoder() throws IOException {
        rekeyCipher(this.cryptoParams.getSecurityParametersConnection(), this.decryptCipher, this.decryptNonce, !this.cryptoParams.isServer());
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public void rekeyEncoder() throws IOException {
        rekeyCipher(this.cryptoParams.getSecurityParametersConnection(), this.encryptCipher, this.encryptNonce, this.cryptoParams.isServer());
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