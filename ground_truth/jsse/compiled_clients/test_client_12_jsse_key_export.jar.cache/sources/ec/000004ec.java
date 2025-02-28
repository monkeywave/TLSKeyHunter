package org.bouncycastle.crypto.macs;

import javassist.bytecode.Opcode;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.CSHAKEDigest;
import org.bouncycastle.crypto.digests.XofUtils;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/macs/KMAC.class */
public class KMAC implements Mac, Xof {
    private static final byte[] padding = new byte[100];
    private final CSHAKEDigest cshake;
    private final int bitLength;
    private final int outputLength;
    private byte[] key;
    private boolean initialised;
    private boolean firstOutput;

    public KMAC(int i, byte[] bArr) {
        this.cshake = new CSHAKEDigest(i, Strings.toByteArray("KMAC"), bArr);
        this.bitLength = i;
        this.outputLength = (i * 2) / 8;
    }

    @Override // org.bouncycastle.crypto.Mac
    public void init(CipherParameters cipherParameters) throws IllegalArgumentException {
        this.key = Arrays.clone(((KeyParameter) cipherParameters).getKey());
        this.initialised = true;
        reset();
    }

    @Override // org.bouncycastle.crypto.Mac
    public String getAlgorithmName() {
        return "KMAC" + this.cshake.getAlgorithmName().substring(6);
    }

    @Override // org.bouncycastle.crypto.ExtendedDigest
    public int getByteLength() {
        return this.cshake.getByteLength();
    }

    @Override // org.bouncycastle.crypto.Mac
    public int getMacSize() {
        return this.outputLength;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return this.outputLength;
    }

    @Override // org.bouncycastle.crypto.Mac
    public void update(byte b) throws IllegalStateException {
        if (!this.initialised) {
            throw new IllegalStateException("KMAC not initialized");
        }
        this.cshake.update(b);
    }

    @Override // org.bouncycastle.crypto.Mac
    public void update(byte[] bArr, int i, int i2) throws DataLengthException, IllegalStateException {
        if (!this.initialised) {
            throw new IllegalStateException("KMAC not initialized");
        }
        this.cshake.update(bArr, i, i2);
    }

    @Override // org.bouncycastle.crypto.Mac
    public int doFinal(byte[] bArr, int i) throws DataLengthException, IllegalStateException {
        if (this.firstOutput) {
            if (!this.initialised) {
                throw new IllegalStateException("KMAC not initialized");
            }
            byte[] rightEncode = XofUtils.rightEncode(getMacSize() * 8);
            this.cshake.update(rightEncode, 0, rightEncode.length);
        }
        int doFinal = this.cshake.doFinal(bArr, i, getMacSize());
        reset();
        return doFinal;
    }

    @Override // org.bouncycastle.crypto.Xof
    public int doFinal(byte[] bArr, int i, int i2) {
        if (this.firstOutput) {
            if (!this.initialised) {
                throw new IllegalStateException("KMAC not initialized");
            }
            byte[] rightEncode = XofUtils.rightEncode(i2 * 8);
            this.cshake.update(rightEncode, 0, rightEncode.length);
        }
        int doFinal = this.cshake.doFinal(bArr, i, i2);
        reset();
        return doFinal;
    }

    @Override // org.bouncycastle.crypto.Xof
    public int doOutput(byte[] bArr, int i, int i2) {
        if (this.firstOutput) {
            if (!this.initialised) {
                throw new IllegalStateException("KMAC not initialized");
            }
            byte[] rightEncode = XofUtils.rightEncode(0L);
            this.cshake.update(rightEncode, 0, rightEncode.length);
            this.firstOutput = false;
        }
        return this.cshake.doOutput(bArr, i, i2);
    }

    @Override // org.bouncycastle.crypto.Mac
    public void reset() {
        this.cshake.reset();
        if (this.key != null) {
            if (this.bitLength == 128) {
                bytePad(this.key, Opcode.JSR);
            } else {
                bytePad(this.key, Opcode.L2I);
            }
        }
        this.firstOutput = true;
    }

    private void bytePad(byte[] bArr, int i) {
        byte[] leftEncode = XofUtils.leftEncode(i);
        update(leftEncode, 0, leftEncode.length);
        byte[] encode = encode(bArr);
        update(encode, 0, encode.length);
        int length = i - ((leftEncode.length + encode.length) % i);
        if (length <= 0 || length == i) {
            return;
        }
        while (length > padding.length) {
            update(padding, 0, padding.length);
            length -= padding.length;
        }
        update(padding, 0, length);
    }

    private static byte[] encode(byte[] bArr) {
        return Arrays.concatenate(XofUtils.leftEncode(bArr.length * 8), bArr);
    }
}