package org.openjsse.com.sun.crypto.provider;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Objects;
import sun.security.util.math.IntegerFieldModuloP;
import sun.security.util.math.IntegerModuloP;
import sun.security.util.math.MutableIntegerModuloP;
import sun.security.util.math.intpoly.IntegerPolynomial1305;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/Poly1305.class */
final class Poly1305 {
    private static final int KEY_LENGTH = 32;
    private static final int RS_LENGTH = 16;
    private static final int BLOCK_LENGTH = 16;
    private static final int TAG_LENGTH = 16;
    private static final IntegerFieldModuloP ipl1305;
    private byte[] keyBytes;
    private int blockOffset;

    /* renamed from: r */
    private IntegerModuloP f950r;

    /* renamed from: s */
    private IntegerModuloP f951s;

    /* renamed from: a */
    private MutableIntegerModuloP f952a;
    static final /* synthetic */ boolean $assertionsDisabled;
    private final byte[] block = new byte[16];

    /* renamed from: n */
    private final MutableIntegerModuloP f953n = ipl1305.get1().mutable();

    static {
        $assertionsDisabled = !Poly1305.class.desiredAssertionStatus();
        ipl1305 = new IntegerPolynomial1305();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void engineInit(Key newKey, AlgorithmParameterSpec params) throws InvalidKeyException {
        Objects.requireNonNull(newKey, "Null key provided during init");
        this.keyBytes = newKey.getEncoded();
        if (this.keyBytes == null) {
            throw new InvalidKeyException("Key does not support encoding");
        }
        if (this.keyBytes.length != 32) {
            throw new InvalidKeyException("Incorrect length for key: " + this.keyBytes.length);
        }
        engineReset();
        setRSVals();
    }

    int engineGetMacLength() {
        return 16;
    }

    void engineReset() {
        Arrays.fill(this.block, (byte) 0);
        this.blockOffset = 0;
        this.f952a = ipl1305.get0().mutable();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void engineUpdate(ByteBuffer buf) {
        int remaining = buf.remaining();
        while (true) {
            int remaining2 = remaining;
            if (remaining2 > 0) {
                int bytesToWrite = Integer.min(remaining2, 16 - this.blockOffset);
                if (bytesToWrite >= 16) {
                    processBlock(buf, bytesToWrite);
                } else {
                    buf.get(this.block, this.blockOffset, bytesToWrite);
                    this.blockOffset += bytesToWrite;
                    if (this.blockOffset >= 16) {
                        processBlock(this.block, 0, 16);
                        this.blockOffset = 0;
                    }
                }
                remaining = remaining2 - bytesToWrite;
            } else {
                return;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void engineUpdate(byte[] input, int offset, int len) {
        checkFromIndexSize(offset, len, input.length);
        if (this.blockOffset > 0) {
            int blockSpaceLeft = 16 - this.blockOffset;
            if (len < blockSpaceLeft) {
                System.arraycopy(input, offset, this.block, this.blockOffset, len);
                this.blockOffset += len;
                return;
            }
            System.arraycopy(input, offset, this.block, this.blockOffset, blockSpaceLeft);
            offset += blockSpaceLeft;
            len -= blockSpaceLeft;
            processBlock(this.block, 0, 16);
            this.blockOffset = 0;
        }
        while (len >= 16) {
            processBlock(input, offset, 16);
            offset += 16;
            len -= 16;
        }
        if (len > 0) {
            System.arraycopy(input, offset, this.block, 0, len);
            this.blockOffset = len;
        }
    }

    void engineUpdate(byte input) {
        if (!$assertionsDisabled && this.blockOffset >= 16) {
            throw new AssertionError();
        }
        byte[] bArr = this.block;
        int i = this.blockOffset;
        this.blockOffset = i + 1;
        bArr[i] = input;
        if (this.blockOffset == 16) {
            processBlock(this.block, 0, 16);
            this.blockOffset = 0;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] engineDoFinal() {
        byte[] tag = new byte[16];
        if (this.blockOffset > 0) {
            processBlock(this.block, 0, this.blockOffset);
            this.blockOffset = 0;
        }
        this.f952a.addModPowerTwo(this.f951s, tag);
        engineReset();
        return tag;
    }

    private void processBlock(ByteBuffer buf, int len) {
        this.f953n.setValue(buf, len, (byte) 1);
        this.f952a.setSum(this.f953n);
        this.f952a.setProduct(this.f950r);
    }

    private void processBlock(byte[] block, int offset, int length) {
        checkFromIndexSize(offset, length, block.length);
        this.f953n.setValue(block, offset, length, (byte) 1);
        this.f952a.setSum(this.f953n);
        this.f952a.setProduct(this.f950r);
    }

    private void setRSVals() {
        byte[] bArr = this.keyBytes;
        bArr[3] = (byte) (bArr[3] & 15);
        byte[] bArr2 = this.keyBytes;
        bArr2[7] = (byte) (bArr2[7] & 15);
        byte[] bArr3 = this.keyBytes;
        bArr3[11] = (byte) (bArr3[11] & 15);
        byte[] bArr4 = this.keyBytes;
        bArr4[15] = (byte) (bArr4[15] & 15);
        byte[] bArr5 = this.keyBytes;
        bArr5[4] = (byte) (bArr5[4] & 252);
        byte[] bArr6 = this.keyBytes;
        bArr6[8] = (byte) (bArr6[8] & 252);
        byte[] bArr7 = this.keyBytes;
        bArr7[12] = (byte) (bArr7[12] & 252);
        this.f950r = ipl1305.getElement(this.keyBytes, 0, 16, (byte) 0);
        this.f951s = ipl1305.getElement(this.keyBytes, 16, 16, (byte) 0);
    }

    private int checkFromIndexSize(int fromIndex, int size, int length) throws IndexOutOfBoundsException {
        if ((length | fromIndex | size) < 0 || size > length - fromIndex) {
            throw new IndexOutOfBoundsException();
        }
        return fromIndex;
    }
}