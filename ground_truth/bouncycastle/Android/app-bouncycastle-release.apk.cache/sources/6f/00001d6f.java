package org.bouncycastle.crypto.engines;

import kotlin.UByte;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.HandshakeType;

/* loaded from: classes2.dex */
public class SkipjackEngine implements BlockCipher {
    static final int BLOCK_SIZE = 8;
    static short[] ftable = {163, 215, 9, 131, 248, 72, 246, 244, 179, 33, 21, AlertDescription.no_application_protocol, 153, 177, 175, 249, 231, 45, 77, 138, 206, 76, 202, 46, 82, 149, 217, 30, 78, 56, 68, 40, 10, 223, 2, 160, 23, 241, 96, 104, 18, 183, 122, 195, 233, 250, 61, 83, 150, 132, 107, 186, 242, 99, 154, 25, 124, 174, 229, 245, 247, 22, 106, 162, 57, 182, 123, 15, 193, 147, 129, 27, 238, 180, 26, 234, 208, 145, 47, 184, 85, 185, 218, 133, 63, 65, 191, 224, 90, 88, 128, 95, 102, 11, 216, 144, 53, 213, 192, 167, 51, 6, 101, 105, 69, 0, 148, 86, AlertDescription.missing_extension, 152, 155, 118, 151, 252, 178, 194, 176, HandshakeType.message_hash, 219, 32, 225, 235, 214, 228, 221, 71, 74, 29, 66, 237, 158, AlertDescription.unsupported_extension, 73, 60, 205, 67, 39, 210, 7, 212, 222, 199, 103, 24, 137, 203, 48, 31, 141, 198, 143, 170, 200, AlertDescription.certificate_required, 220, 201, 93, 92, 49, 164, AlertDescription.unrecognized_name, 136, 97, 44, 159, 13, 43, 135, 80, 130, 84, 100, 38, 125, 3, 64, 52, 75, 28, AlertDescription.unknown_psk_identity, 209, 196, 253, 59, 204, 251, 127, 171, 230, 62, 91, 165, 173, 4, 35, 156, 20, 81, 34, 240, 41, 121, AlertDescription.bad_certificate_status_response, 126, 255, 140, 14, 226, 12, 239, 188, AlertDescription.bad_certificate_hash_value, 117, AlertDescription.certificate_unobtainable, 55, 161, 236, 211, 142, 98, 139, 134, 16, 232, 8, 119, 17, 190, 146, 79, 36, 197, 50, 54, 157, 207, 243, 166, 187, 172, 94, 108, 169, 19, 87, 37, 181, 227, 189, 168, 58, 1, 5, 89, 42, 70};
    private boolean encrypting;
    private int[] key0;
    private int[] key1;
    private int[] key2;
    private int[] key3;

    public SkipjackEngine() {
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(getAlgorithmName(), 80));
    }

    /* renamed from: g */
    private int m54g(int i, int i2) {
        int i3 = i2 & 255;
        short[] sArr = ftable;
        int i4 = ((i2 >> 8) & 255) ^ sArr[this.key0[i] ^ i3];
        int i5 = i3 ^ sArr[this.key1[i] ^ i4];
        int i6 = i4 ^ sArr[this.key2[i] ^ i5];
        return (i6 << 8) + (sArr[this.key3[i] ^ i6] ^ i5);
    }

    private CryptoServicePurpose getPurpose() {
        return this.key0 == null ? CryptoServicePurpose.ANY : this.encrypting ? CryptoServicePurpose.ENCRYPTION : CryptoServicePurpose.DECRYPTION;
    }

    /* renamed from: h */
    private int m53h(int i, int i2) {
        int i3 = i2 & 255;
        int i4 = (i2 >> 8) & 255;
        short[] sArr = ftable;
        int i5 = i3 ^ sArr[this.key3[i] ^ i4];
        int i6 = i4 ^ sArr[this.key2[i] ^ i5];
        int i7 = i5 ^ sArr[this.key1[i] ^ i6];
        return ((sArr[this.key0[i] ^ i7] ^ i6) << 8) + i7;
    }

    public int decryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        int i3 = (bArr[i] << 8) + (bArr[i + 1] & UByte.MAX_VALUE);
        int i4 = (bArr[i + 2] << 8) + (bArr[i + 3] & UByte.MAX_VALUE);
        int i5 = (bArr[i + 4] << 8) + (bArr[i + 5] & UByte.MAX_VALUE);
        int i6 = (bArr[i + 6] << 8) + (bArr[i + 7] & UByte.MAX_VALUE);
        int i7 = 31;
        for (int i8 = 0; i8 < 2; i8++) {
            int i9 = 0;
            while (i9 < 8) {
                int m53h = m53h(i7, i4);
                i7--;
                i9++;
                int i10 = i6;
                i6 = i3;
                i3 = m53h;
                i4 = (i5 ^ m53h) ^ (i7 + 1);
                i5 = i10;
            }
            int i11 = 0;
            while (i11 < 8) {
                int m53h2 = m53h(i7, i4);
                i7--;
                i11++;
                int i12 = i6;
                i6 = (i3 ^ i4) ^ (i7 + 1);
                i3 = m53h2;
                i4 = i5;
                i5 = i12;
            }
        }
        bArr2[i2] = (byte) (i3 >> 8);
        bArr2[i2 + 1] = (byte) i3;
        bArr2[i2 + 2] = (byte) (i4 >> 8);
        bArr2[i2 + 3] = (byte) i4;
        bArr2[i2 + 4] = (byte) (i5 >> 8);
        bArr2[i2 + 5] = (byte) i5;
        bArr2[i2 + 6] = (byte) (i6 >> 8);
        bArr2[i2 + 7] = (byte) i6;
        return 8;
    }

    public int encryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        int i3 = (bArr[i] << 8) + (bArr[i + 1] & UByte.MAX_VALUE);
        int i4 = (bArr[i + 2] << 8) + (bArr[i + 3] & UByte.MAX_VALUE);
        int i5 = (bArr[i + 4] << 8) + (bArr[i + 5] & UByte.MAX_VALUE);
        int i6 = (bArr[i + 6] << 8) + (bArr[i + 7] & UByte.MAX_VALUE);
        int i7 = 0;
        for (int i8 = 0; i8 < 2; i8++) {
            int i9 = 0;
            while (i9 < 8) {
                int m54g = m54g(i7, i3);
                i7++;
                i9++;
                int i10 = i4;
                i4 = m54g;
                i3 = (i6 ^ m54g) ^ i7;
                i6 = i5;
                i5 = i10;
            }
            int i11 = 0;
            while (i11 < 8) {
                int i12 = i7 + 1;
                int i13 = (i4 ^ i3) ^ i12;
                int m54g2 = m54g(i7, i3);
                i11++;
                i7 = i12;
                i4 = m54g2;
                i3 = i6;
                i6 = i5;
                i5 = i13;
            }
        }
        bArr2[i2] = (byte) (i3 >> 8);
        bArr2[i2 + 1] = (byte) i3;
        bArr2[i2 + 2] = (byte) (i4 >> 8);
        bArr2[i2 + 3] = (byte) i4;
        bArr2[i2 + 4] = (byte) (i5 >> 8);
        bArr2[i2 + 5] = (byte) i5;
        bArr2[i2 + 6] = (byte) (i6 >> 8);
        bArr2[i2 + 7] = (byte) i6;
        return 8;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return "SKIPJACK";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return 8;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        if (!(cipherParameters instanceof KeyParameter)) {
            throw new IllegalArgumentException("invalid parameter passed to SKIPJACK init - " + cipherParameters.getClass().getName());
        }
        byte[] key = ((KeyParameter) cipherParameters).getKey();
        this.encrypting = z;
        this.key0 = new int[32];
        this.key1 = new int[32];
        this.key2 = new int[32];
        this.key3 = new int[32];
        for (int i = 0; i < 32; i++) {
            int i2 = i * 4;
            this.key0[i] = key[i2 % 10] & UByte.MAX_VALUE;
            this.key1[i] = key[(i2 + 1) % 10] & UByte.MAX_VALUE;
            this.key2[i] = key[(i2 + 2) % 10] & UByte.MAX_VALUE;
            this.key3[i] = key[(i2 + 3) % 10] & UByte.MAX_VALUE;
        }
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(getAlgorithmName(), 80, cipherParameters, getPurpose()));
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        if (this.key1 != null) {
            if (i + 8 <= bArr.length) {
                if (i2 + 8 <= bArr2.length) {
                    if (this.encrypting) {
                        encryptBlock(bArr, i, bArr2, i2);
                        return 8;
                    }
                    decryptBlock(bArr, i, bArr2, i2);
                    return 8;
                }
                throw new OutputLengthException("output buffer too short");
            }
            throw new DataLengthException("input buffer too short");
        }
        throw new IllegalStateException("SKIPJACK engine not initialised");
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
    }
}