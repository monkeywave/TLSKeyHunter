package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/Shacal2Engine.class */
public class Shacal2Engine implements BlockCipher {

    /* renamed from: K */
    private static final int[] f376K = {1116352408, 1899447441, -1245643825, -373957723, 961987163, 1508970993, -1841331548, -1424204075, -670586216, 310598401, 607225278, 1426881987, 1925078388, -2132889090, -1680079193, -1046744716, -459576895, -272742522, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, -1740746414, -1473132947, -1341970488, -1084653625, -958395405, -710438585, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, -2117940946, -1838011259, -1564481375, -1474664885, -1035236496, -949202525, -778901479, -694614492, -200395387, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, -2067236844, -1933114872, -1866530822, -1538233109, -1090935817, -965641998};
    private static final int BLOCK_SIZE = 32;
    private static final int ROUNDS = 64;
    private boolean forEncryption = false;
    private int[] workingKey = null;

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return "Shacal2";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return 32;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        if (!(cipherParameters instanceof KeyParameter)) {
            throw new IllegalArgumentException("only simple KeyParameter expected.");
        }
        this.forEncryption = z;
        this.workingKey = new int[64];
        setKey(((KeyParameter) cipherParameters).getKey());
    }

    public void setKey(byte[] bArr) {
        if (bArr.length == 0 || bArr.length > 64 || bArr.length < 16 || bArr.length % 8 != 0) {
            throw new IllegalArgumentException("Shacal2-key must be 16 - 64 bytes and multiple of 8");
        }
        bytes2ints(bArr, this.workingKey, 0, 0);
        for (int i = 16; i < 64; i++) {
            this.workingKey[i] = ((((this.workingKey[i - 2] >>> 17) | (this.workingKey[i - 2] << (-17))) ^ ((this.workingKey[i - 2] >>> 19) | (this.workingKey[i - 2] << (-19)))) ^ (this.workingKey[i - 2] >>> 10)) + this.workingKey[i - 7] + ((((this.workingKey[i - 15] >>> 7) | (this.workingKey[i - 15] << (-7))) ^ ((this.workingKey[i - 15] >>> 18) | (this.workingKey[i - 15] << (-18)))) ^ (this.workingKey[i - 15] >>> 3)) + this.workingKey[i - 16];
        }
    }

    private void encryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        int[] iArr = new int[8];
        byteBlockToInts(bArr, iArr, i, 0);
        for (int i3 = 0; i3 < 64; i3++) {
            int i4 = ((((iArr[4] >>> 6) | (iArr[4] << (-6))) ^ ((iArr[4] >>> 11) | (iArr[4] << (-11)))) ^ ((iArr[4] >>> 25) | (iArr[4] << (-25)))) + ((iArr[4] & iArr[5]) ^ ((iArr[4] ^ (-1)) & iArr[6])) + iArr[7] + f376K[i3] + this.workingKey[i3];
            iArr[7] = iArr[6];
            iArr[6] = iArr[5];
            iArr[5] = iArr[4];
            iArr[4] = iArr[3] + i4;
            iArr[3] = iArr[2];
            iArr[2] = iArr[1];
            iArr[1] = iArr[0];
            iArr[0] = i4 + ((((iArr[0] >>> 2) | (iArr[0] << (-2))) ^ ((iArr[0] >>> 13) | (iArr[0] << (-13)))) ^ ((iArr[0] >>> 22) | (iArr[0] << (-22)))) + (((iArr[0] & iArr[2]) ^ (iArr[0] & iArr[3])) ^ (iArr[2] & iArr[3]));
        }
        ints2bytes(iArr, bArr2, i2);
    }

    private void decryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        int[] iArr = new int[8];
        byteBlockToInts(bArr, iArr, i, 0);
        for (int i3 = 63; i3 > -1; i3--) {
            int i4 = (iArr[0] - ((((iArr[1] >>> 2) | (iArr[1] << (-2))) ^ ((iArr[1] >>> 13) | (iArr[1] << (-13)))) ^ ((iArr[1] >>> 22) | (iArr[1] << (-22))))) - (((iArr[1] & iArr[2]) ^ (iArr[1] & iArr[3])) ^ (iArr[2] & iArr[3]));
            iArr[0] = iArr[1];
            iArr[1] = iArr[2];
            iArr[2] = iArr[3];
            iArr[3] = iArr[4] - i4;
            iArr[4] = iArr[5];
            iArr[5] = iArr[6];
            iArr[6] = iArr[7];
            iArr[7] = (((i4 - f376K[i3]) - this.workingKey[i3]) - ((((iArr[4] >>> 6) | (iArr[4] << (-6))) ^ ((iArr[4] >>> 11) | (iArr[4] << (-11)))) ^ ((iArr[4] >>> 25) | (iArr[4] << (-25))))) - ((iArr[4] & iArr[5]) ^ ((iArr[4] ^ (-1)) & iArr[6]));
        }
        ints2bytes(iArr, bArr2, i2);
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        if (this.workingKey == null) {
            throw new IllegalStateException("Shacal2 not initialised");
        }
        if (i + 32 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        if (i2 + 32 > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        }
        if (this.forEncryption) {
            encryptBlock(bArr, i, bArr2, i2);
            return 32;
        }
        decryptBlock(bArr, i, bArr2, i2);
        return 32;
    }

    private void byteBlockToInts(byte[] bArr, int[] iArr, int i, int i2) {
        for (int i3 = i2; i3 < 8; i3++) {
            int i4 = i;
            int i5 = i + 1;
            int i6 = i5 + 1;
            int i7 = i6 + 1;
            i = i7 + 1;
            iArr[i3] = ((bArr[i4] & GF2Field.MASK) << 24) | ((bArr[i5] & GF2Field.MASK) << 16) | ((bArr[i6] & GF2Field.MASK) << 8) | (bArr[i7] & GF2Field.MASK);
        }
    }

    private void bytes2ints(byte[] bArr, int[] iArr, int i, int i2) {
        for (int i3 = i2; i3 < bArr.length / 4; i3++) {
            int i4 = i;
            int i5 = i + 1;
            int i6 = i5 + 1;
            int i7 = i6 + 1;
            i = i7 + 1;
            iArr[i3] = ((bArr[i4] & GF2Field.MASK) << 24) | ((bArr[i5] & GF2Field.MASK) << 16) | ((bArr[i6] & GF2Field.MASK) << 8) | (bArr[i7] & GF2Field.MASK);
        }
    }

    private void ints2bytes(int[] iArr, byte[] bArr, int i) {
        for (int i2 = 0; i2 < iArr.length; i2++) {
            int i3 = i;
            int i4 = i + 1;
            bArr[i3] = (byte) (iArr[i2] >>> 24);
            int i5 = i4 + 1;
            bArr[i4] = (byte) (iArr[i2] >>> 16);
            int i6 = i5 + 1;
            bArr[i5] = (byte) (iArr[i2] >>> 8);
            i = i6 + 1;
            bArr[i6] = (byte) iArr[i2];
        }
    }
}