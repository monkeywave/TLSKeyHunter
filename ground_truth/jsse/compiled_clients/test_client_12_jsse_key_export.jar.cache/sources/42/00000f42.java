package org.openjsse.com.sun.crypto.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.AEADBadTagException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.openjsse.javax.crypto.spec.ChaCha20ParameterSpec;
import sun.security.util.DerValue;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/ChaCha20Cipher.class */
public abstract class ChaCha20Cipher extends CipherSpi {
    private static final int MODE_NONE = 0;
    private static final int MODE_AEAD = 1;
    private static final int STATE_CONST_0 = 1634760805;
    private static final int STATE_CONST_1 = 857760878;
    private static final int STATE_CONST_2 = 2036477234;
    private static final int STATE_CONST_3 = 1797285236;
    private static final int KEYSTREAM_SIZE = 64;
    private static final int KS_SIZE_INTS = 16;
    private static final int CIPHERBUF_BASE = 1024;
    private boolean initialized;
    protected int mode;
    private int direction;
    private byte[] keyBytes;
    private byte[] nonce;
    private static final long MAX_UINT32 = 4294967295L;
    private long finalCounterValue;
    private long counter;
    private int keyStrOffset;
    private static final int TAG_LENGTH = 16;
    private long aadLen;
    private long dataLen;
    private static final byte[] padBuf = new byte[16];
    protected String authAlgName;
    private Poly1305 authenticator;
    private ChaChaEngine engine;
    private boolean aadDone = false;
    private final int[] startState = new int[16];
    private final byte[] keyStream = new byte[64];
    private final byte[] lenBuf = new byte[16];

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/ChaCha20Cipher$ChaChaEngine.class */
    public interface ChaChaEngine {
        int getOutputSize(int i, boolean z);

        int doUpdate(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws ShortBufferException, KeyException;

        int doFinal(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws ShortBufferException, AEADBadTagException, KeyException;
    }

    protected ChaCha20Cipher() {
    }

    @Override // javax.crypto.CipherSpi
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!mode.equalsIgnoreCase("None")) {
            throw new NoSuchAlgorithmException("Mode must be None");
        }
    }

    @Override // javax.crypto.CipherSpi
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!padding.equalsIgnoreCase("NoPadding")) {
            throw new NoSuchPaddingException("Padding must be NoPadding");
        }
    }

    @Override // javax.crypto.CipherSpi
    protected int engineGetBlockSize() {
        return 0;
    }

    @Override // javax.crypto.CipherSpi
    protected int engineGetOutputSize(int inputLen) {
        return this.engine.getOutputSize(inputLen, true);
    }

    @Override // javax.crypto.CipherSpi
    protected byte[] engineGetIV() {
        return (byte[]) this.nonce.clone();
    }

    @Override // javax.crypto.CipherSpi
    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters params = null;
        if (this.mode == 1) {
            try {
                params = AlgorithmParameters.getInstance("ChaCha20-Poly1305");
                params.init(new DerValue((byte) 4, this.nonce).toByteArray());
            } catch (IOException | NoSuchAlgorithmException exc) {
                throw new RuntimeException(exc);
            }
        }
        return params;
    }

    @Override // javax.crypto.CipherSpi
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if (opmode != 2) {
            byte[] newNonce = createRandomNonce(random);
            this.counter = 1L;
            init(opmode, key, newNonce);
            return;
        }
        throw new InvalidKeyException("Default parameter generation disallowed in DECRYPT and UNWRAP modes");
    }

    @Override // javax.crypto.CipherSpi
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        byte[] newNonce;
        if (params == null) {
            engineInit(opmode, key, random);
            return;
        }
        switch (this.mode) {
            case 0:
                if (!(params instanceof ChaCha20ParameterSpec)) {
                    throw new InvalidAlgorithmParameterException("ChaCha20 algorithm requires ChaCha20ParameterSpec");
                }
                ChaCha20ParameterSpec chaParams = (ChaCha20ParameterSpec) params;
                newNonce = chaParams.getNonce();
                this.counter = chaParams.getCounter() & MAX_UINT32;
                break;
            case 1:
                if (!(params instanceof IvParameterSpec)) {
                    throw new InvalidAlgorithmParameterException("ChaCha20-Poly1305 requires IvParameterSpec");
                }
                IvParameterSpec ivParams = (IvParameterSpec) params;
                newNonce = ivParams.getIV();
                if (newNonce.length != 12) {
                    throw new InvalidAlgorithmParameterException("ChaCha20-Poly1305 nonce must be 12 bytes in length");
                }
                break;
            default:
                throw new RuntimeException("ChaCha20 in unsupported mode");
        }
        init(opmode, key, newNonce);
    }

    @Override // javax.crypto.CipherSpi
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params == null) {
            engineInit(opmode, key, random);
            return;
        }
        switch (this.mode) {
            case 0:
                throw new InvalidAlgorithmParameterException("AlgorithmParameters not supported");
            case 1:
                String paramAlg = params.getAlgorithm();
                if (!paramAlg.equalsIgnoreCase("ChaCha20-Poly1305")) {
                    throw new InvalidAlgorithmParameterException("Invalid parameter type: " + paramAlg);
                }
                try {
                    DerValue dv = new DerValue(params.getEncoded());
                    byte[] newNonce = dv.getOctetString();
                    if (newNonce.length != 12) {
                        throw new InvalidAlgorithmParameterException("ChaCha20-Poly1305 nonce must be 12 bytes in length");
                    }
                    if (newNonce == null) {
                        newNonce = createRandomNonce(random);
                    }
                    init(opmode, key, newNonce);
                    return;
                } catch (IOException ioe) {
                    throw new InvalidAlgorithmParameterException(ioe);
                }
            default:
                throw new RuntimeException("Invalid mode: " + this.mode);
        }
    }

    @Override // javax.crypto.CipherSpi
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        if (!this.initialized) {
            throw new IllegalStateException("Attempted to update AAD on uninitialized Cipher");
        }
        if (this.aadDone) {
            throw new IllegalStateException("Attempted to update AAD on Cipher after plaintext/ciphertext update");
        }
        if (this.mode != 1) {
            throw new IllegalStateException("Cipher is running in non-AEAD mode");
        }
        try {
            this.aadLen = Math.addExact(this.aadLen, len);
            authUpdate(src, offset, len);
        } catch (ArithmeticException ae) {
            throw new IllegalStateException("AAD overflow", ae);
        }
    }

    @Override // javax.crypto.CipherSpi
    protected void engineUpdateAAD(ByteBuffer src) {
        if (!this.initialized) {
            throw new IllegalStateException("Attempted to update AAD on uninitialized Cipher");
        }
        if (this.aadDone) {
            throw new IllegalStateException("Attempted to update AAD on Cipher after plaintext/ciphertext update");
        }
        if (this.mode != 1) {
            throw new IllegalStateException("Cipher is running in non-AEAD mode");
        }
        try {
            this.aadLen = Math.addExact(this.aadLen, src.limit() - src.position());
            this.authenticator.engineUpdate(src);
        } catch (ArithmeticException ae) {
            throw new IllegalStateException("AAD overflow", ae);
        }
    }

    private byte[] createRandomNonce(SecureRandom random) {
        byte[] newNonce = new byte[12];
        SecureRandom rand = random != null ? random : new SecureRandom();
        rand.nextBytes(newNonce);
        return newNonce;
    }

    private void init(int opmode, Key key, byte[] newNonce) throws InvalidKeyException {
        if (opmode == 3 || opmode == 4) {
            throw new UnsupportedOperationException("WRAP_MODE and UNWRAP_MODE are not currently supported");
        }
        if (opmode != 1 && opmode != 2) {
            throw new InvalidKeyException("Unknown opmode: " + opmode);
        }
        byte[] newKeyBytes = getEncodedKey(key);
        checkKeyAndNonce(newKeyBytes, newNonce);
        this.keyBytes = newKeyBytes;
        this.nonce = newNonce;
        setInitialState();
        if (this.mode == 0) {
            this.engine = new EngineStreamOnly();
        } else if (this.mode == 1) {
            if (opmode == 1) {
                this.engine = new EngineAEADEnc();
            } else if (opmode == 2) {
                this.engine = new EngineAEADDec();
            } else {
                throw new InvalidKeyException("Not encrypt or decrypt mode");
            }
        }
        this.finalCounterValue = this.counter + MAX_UINT32;
        generateKeystream();
        this.direction = opmode;
        this.aadDone = false;
        this.keyStrOffset = 0;
        this.initialized = true;
    }

    private void checkKeyAndNonce(byte[] newKeyBytes, byte[] newNonce) throws InvalidKeyException {
        if (MessageDigest.isEqual(newKeyBytes, this.keyBytes) && MessageDigest.isEqual(newNonce, this.nonce)) {
            throw new InvalidKeyException("Matching key and nonce from previous initialization");
        }
    }

    private static byte[] getEncodedKey(Key key) throws InvalidKeyException {
        if (!"RAW".equals(key.getFormat())) {
            throw new InvalidKeyException("Key encoding format must be RAW");
        }
        byte[] encodedKey = key.getEncoded();
        if (encodedKey == null || encodedKey.length != 32) {
            throw new InvalidKeyException("Key length must be 256 bits");
        }
        return encodedKey;
    }

    @Override // javax.crypto.CipherSpi
    protected byte[] engineUpdate(byte[] in, int inOfs, int inLen) {
        byte[] out = new byte[this.engine.getOutputSize(inLen, false)];
        try {
            this.engine.doUpdate(in, inOfs, inLen, out, 0);
            return out;
        } catch (KeyException | ShortBufferException exc) {
            throw new RuntimeException(exc);
        }
    }

    @Override // javax.crypto.CipherSpi
    protected int engineUpdate(byte[] in, int inOfs, int inLen, byte[] out, int outOfs) throws ShortBufferException {
        try {
            int bytesUpdated = this.engine.doUpdate(in, inOfs, inLen, out, outOfs);
            return bytesUpdated;
        } catch (KeyException ke) {
            throw new RuntimeException(ke);
        }
    }

    @Override // javax.crypto.CipherSpi
    protected byte[] engineDoFinal(byte[] in, int inOfs, int inLen) throws AEADBadTagException {
        byte[] output = new byte[this.engine.getOutputSize(inLen, true)];
        try {
            try {
                this.engine.doFinal(in, inOfs, inLen, output, 0);
                this.initialized = false;
                return output;
            } catch (KeyException | ShortBufferException exc) {
                throw new RuntimeException(exc);
            }
        } catch (Throwable th) {
            this.initialized = false;
            throw th;
        }
    }

    @Override // javax.crypto.CipherSpi
    protected int engineDoFinal(byte[] in, int inOfs, int inLen, byte[] out, int outOfs) throws ShortBufferException, AEADBadTagException {
        try {
            try {
                int bytesUpdated = this.engine.doFinal(in, inOfs, inLen, out, outOfs);
                this.initialized = false;
                return bytesUpdated;
            } catch (KeyException ke) {
                throw new RuntimeException(ke);
            }
        } catch (Throwable th) {
            this.initialized = false;
            throw th;
        }
    }

    @Override // javax.crypto.CipherSpi
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        throw new UnsupportedOperationException("Wrap operations are not supported");
    }

    @Override // javax.crypto.CipherSpi
    protected Key engineUnwrap(byte[] wrappedKey, String algorithm, int type) throws InvalidKeyException, NoSuchAlgorithmException {
        throw new UnsupportedOperationException("Unwrap operations are not supported");
    }

    @Override // javax.crypto.CipherSpi
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        byte[] encodedKey = getEncodedKey(key);
        return encodedKey.length << 3;
    }

    private void setInitialState() throws InvalidKeyException {
        this.startState[0] = STATE_CONST_0;
        this.startState[1] = STATE_CONST_1;
        this.startState[2] = STATE_CONST_2;
        this.startState[3] = STATE_CONST_3;
        for (int i = 0; i < 32; i += 4) {
            this.startState[(i / 4) + 4] = (this.keyBytes[i] & 255) | ((this.keyBytes[i + 1] << 8) & 65280) | ((this.keyBytes[i + 2] << 16) & 16711680) | ((this.keyBytes[i + 3] << 24) & (-16777216));
        }
        this.startState[12] = 0;
        for (int i2 = 0; i2 < 12; i2 += 4) {
            this.startState[(i2 / 4) + 13] = (this.nonce[i2] & 255) | ((this.nonce[i2 + 1] << 8) & 65280) | ((this.nonce[i2 + 2] << 16) & 16711680) | ((this.nonce[i2 + 3] << 24) & (-16777216));
        }
    }

    private void generateKeystream() {
        chaCha20Block(this.startState, this.counter, this.keyStream);
        this.counter++;
    }

    private static void chaCha20Block(int[] initState, long counter, byte[] result) {
        int ws00 = STATE_CONST_0;
        int ws01 = STATE_CONST_1;
        int ws02 = STATE_CONST_2;
        int ws03 = STATE_CONST_3;
        int ws04 = initState[4];
        int ws05 = initState[5];
        int ws06 = initState[6];
        int ws07 = initState[7];
        int ws08 = initState[8];
        int ws09 = initState[9];
        int ws10 = initState[10];
        int ws11 = initState[11];
        int ws12 = (int) counter;
        int ws13 = initState[13];
        int ws14 = initState[14];
        int ws15 = initState[15];
        for (int round = 0; round < 10; round++) {
            int ws002 = ws00 + ws04;
            int ws122 = Integer.rotateLeft(ws12 ^ ws002, 16);
            int ws082 = ws08 + ws122;
            int ws042 = Integer.rotateLeft(ws04 ^ ws082, 12);
            int ws003 = ws002 + ws042;
            int ws123 = Integer.rotateLeft(ws122 ^ ws003, 8);
            int ws083 = ws082 + ws123;
            int ws043 = Integer.rotateLeft(ws042 ^ ws083, 7);
            int ws012 = ws01 + ws05;
            int ws132 = Integer.rotateLeft(ws13 ^ ws012, 16);
            int ws092 = ws09 + ws132;
            int ws052 = Integer.rotateLeft(ws05 ^ ws092, 12);
            int ws013 = ws012 + ws052;
            int ws133 = Integer.rotateLeft(ws132 ^ ws013, 8);
            int ws093 = ws092 + ws133;
            int ws053 = Integer.rotateLeft(ws052 ^ ws093, 7);
            int ws022 = ws02 + ws06;
            int ws142 = Integer.rotateLeft(ws14 ^ ws022, 16);
            int ws102 = ws10 + ws142;
            int ws062 = Integer.rotateLeft(ws06 ^ ws102, 12);
            int ws023 = ws022 + ws062;
            int ws143 = Integer.rotateLeft(ws142 ^ ws023, 8);
            int ws103 = ws102 + ws143;
            int ws063 = Integer.rotateLeft(ws062 ^ ws103, 7);
            int ws032 = ws03 + ws07;
            int ws152 = Integer.rotateLeft(ws15 ^ ws032, 16);
            int ws112 = ws11 + ws152;
            int ws072 = Integer.rotateLeft(ws07 ^ ws112, 12);
            int ws033 = ws032 + ws072;
            int ws153 = Integer.rotateLeft(ws152 ^ ws033, 8);
            int ws113 = ws112 + ws153;
            int ws073 = Integer.rotateLeft(ws072 ^ ws113, 7);
            int ws004 = ws003 + ws053;
            int ws154 = Integer.rotateLeft(ws153 ^ ws004, 16);
            int ws104 = ws103 + ws154;
            int ws054 = Integer.rotateLeft(ws053 ^ ws104, 12);
            ws00 = ws004 + ws054;
            ws15 = Integer.rotateLeft(ws154 ^ ws00, 8);
            ws10 = ws104 + ws15;
            ws05 = Integer.rotateLeft(ws054 ^ ws10, 7);
            int ws014 = ws013 + ws063;
            int ws124 = Integer.rotateLeft(ws123 ^ ws014, 16);
            int ws114 = ws113 + ws124;
            int ws064 = Integer.rotateLeft(ws063 ^ ws114, 12);
            ws01 = ws014 + ws064;
            ws12 = Integer.rotateLeft(ws124 ^ ws01, 8);
            ws11 = ws114 + ws12;
            ws06 = Integer.rotateLeft(ws064 ^ ws11, 7);
            int ws024 = ws023 + ws073;
            int ws134 = Integer.rotateLeft(ws133 ^ ws024, 16);
            int ws084 = ws083 + ws134;
            int ws074 = Integer.rotateLeft(ws073 ^ ws084, 12);
            ws02 = ws024 + ws074;
            ws13 = Integer.rotateLeft(ws134 ^ ws02, 8);
            ws08 = ws084 + ws13;
            ws07 = Integer.rotateLeft(ws074 ^ ws08, 7);
            int ws034 = ws033 + ws043;
            int ws144 = Integer.rotateLeft(ws143 ^ ws034, 16);
            int ws094 = ws093 + ws144;
            int ws044 = Integer.rotateLeft(ws043 ^ ws094, 12);
            ws03 = ws034 + ws044;
            ws14 = Integer.rotateLeft(ws144 ^ ws03, 8);
            ws09 = ws094 + ws14;
            ws04 = Integer.rotateLeft(ws044 ^ ws09, 7);
        }
        ByteBuffer bb = ByteBuffer.allocate(64);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(ws00 + STATE_CONST_0);
        bb.putInt(ws01 + STATE_CONST_1);
        bb.putInt(ws02 + STATE_CONST_2);
        bb.putInt(ws03 + STATE_CONST_3);
        bb.putInt(ws04 + initState[4]);
        bb.putInt(ws05 + initState[5]);
        bb.putInt(ws06 + initState[6]);
        bb.putInt(ws07 + initState[7]);
        bb.putInt(ws08 + initState[8]);
        bb.putInt(ws09 + initState[9]);
        bb.putInt(ws10 + initState[10]);
        bb.putInt(ws11 + initState[11]);
        bb.putInt(ws12 + ((int) counter));
        bb.putInt(ws13 + initState[13]);
        bb.putInt(ws14 + initState[14]);
        bb.putInt(ws15 + initState[15]);
        bb.rewind();
        bb.get(result);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void chaCha20Transform(byte[] in, int inOff, int inLen, byte[] out, int outOff) throws KeyException {
        int i = inLen;
        while (true) {
            int remainingData = i;
            if (remainingData > 0) {
                int ksRemain = this.keyStream.length - this.keyStrOffset;
                if (ksRemain <= 0) {
                    if (this.counter <= this.finalCounterValue) {
                        generateKeystream();
                        this.keyStrOffset = 0;
                        ksRemain = this.keyStream.length;
                    } else {
                        throw new KeyException("Counter exhausted.  Reinitialize with new key and/or nonce");
                    }
                }
                int xformLen = Math.min(remainingData, ksRemain);
                xor(this.keyStream, this.keyStrOffset, in, inOff, out, outOff, xformLen);
                outOff += xformLen;
                inOff += xformLen;
                this.keyStrOffset += xformLen;
                i = remainingData - xformLen;
            } else {
                return;
            }
        }
    }

    private static void xor(byte[] in1, int off1, byte[] in2, int off2, byte[] out, int outOff, int len) {
        ByteBuffer bb = ByteBuffer.allocate(16);
        bb.order(ByteOrder.nativeOrder());
        while (len >= 8) {
            bb.rewind();
            bb.put(in1, off1, 8);
            bb.put(in2, off2, 8);
            long v1 = bb.getLong(0);
            long v2 = bb.getLong(8);
            bb.putLong(0, v1 ^ v2);
            bb.rewind();
            bb.get(out, outOff, 8);
            off1 += 8;
            off2 += 8;
            outOff += 8;
            len -= 8;
        }
        while (len > 0) {
            out[outOff] = (byte) (in1[off1] ^ in2[off2]);
            off1++;
            off2++;
            outOff++;
            len--;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void initAuthenticator() throws InvalidKeyException {
        this.authenticator = new Poly1305();
        byte[] serializedKey = new byte[64];
        chaCha20Block(this.startState, 0L, serializedKey);
        this.authenticator.engineInit(new SecretKeySpec(serializedKey, 0, 32, this.authAlgName), null);
        this.aadLen = 0L;
        this.dataLen = 0L;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int authUpdate(byte[] data, int offset, int length) {
        checkFromIndexSize(offset, length, data.length);
        this.authenticator.engineUpdate(data, offset, length);
        return length;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void authFinalizeData(byte[] data, int dataOff, int length, byte[] out, int outOff) throws ShortBufferException {
        if (data != null) {
            this.dataLen += authUpdate(data, dataOff, length);
        }
        authPad16(this.dataLen);
        authWriteLengths(this.aadLen, this.dataLen, this.lenBuf);
        this.authenticator.engineUpdate(this.lenBuf, 0, this.lenBuf.length);
        byte[] tag = this.authenticator.engineDoFinal();
        checkFromIndexSize(outOff, tag.length, out.length);
        System.arraycopy(tag, 0, out, outOff, tag.length);
        this.aadLen = 0L;
        this.dataLen = 0L;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void authPad16(long dataLen) {
        this.authenticator.engineUpdate(padBuf, 0, (16 - (((int) dataLen) & 15)) & 15);
    }

    private void authWriteLengths(long aLen, long dLen, byte[] buf) {
        ByteBuffer bb = ByteBuffer.allocate(16);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        bb.putLong(aLen);
        bb.putLong(dLen);
        bb.rewind();
        bb.get(buf, 0, 16);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int checkFromIndexSize(int fromIndex, int size, int length) throws IndexOutOfBoundsException {
        if ((length | fromIndex | size) < 0 || size > length - fromIndex) {
            throw new IndexOutOfBoundsException();
        }
        return fromIndex;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/ChaCha20Cipher$EngineStreamOnly.class */
    public final class EngineStreamOnly implements ChaChaEngine {
        private EngineStreamOnly() {
        }

        @Override // org.openjsse.com.sun.crypto.provider.ChaCha20Cipher.ChaChaEngine
        public int getOutputSize(int inLength, boolean isFinal) {
            return inLength;
        }

        @Override // org.openjsse.com.sun.crypto.provider.ChaCha20Cipher.ChaChaEngine
        public int doUpdate(byte[] in, int inOff, int inLen, byte[] out, int outOff) throws ShortBufferException, KeyException {
            if (ChaCha20Cipher.this.initialized) {
                try {
                    if (out != null) {
                        ChaCha20Cipher.this.checkFromIndexSize(outOff, inLen, out.length);
                        if (in != null) {
                            ChaCha20Cipher.this.checkFromIndexSize(inOff, inLen, in.length);
                            ChaCha20Cipher.this.chaCha20Transform(in, inOff, inLen, out, outOff);
                        }
                        return inLen;
                    }
                    throw new ShortBufferException("Output buffer too small");
                } catch (IndexOutOfBoundsException e) {
                    throw new ShortBufferException("Output buffer too small");
                }
            }
            throw new IllegalStateException("Must use either a different key or iv.");
        }

        @Override // org.openjsse.com.sun.crypto.provider.ChaCha20Cipher.ChaChaEngine
        public int doFinal(byte[] in, int inOff, int inLen, byte[] out, int outOff) throws ShortBufferException, KeyException {
            return doUpdate(in, inOff, inLen, out, outOff);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/ChaCha20Cipher$EngineAEADEnc.class */
    public final class EngineAEADEnc implements ChaChaEngine {
        @Override // org.openjsse.com.sun.crypto.provider.ChaCha20Cipher.ChaChaEngine
        public int getOutputSize(int inLength, boolean isFinal) {
            return isFinal ? Math.addExact(inLength, 16) : inLength;
        }

        private EngineAEADEnc() throws InvalidKeyException {
            ChaCha20Cipher.this.initAuthenticator();
            ChaCha20Cipher.this.counter = 1L;
        }

        @Override // org.openjsse.com.sun.crypto.provider.ChaCha20Cipher.ChaChaEngine
        public int doUpdate(byte[] in, int inOff, int inLen, byte[] out, int outOff) throws ShortBufferException, KeyException {
            if (ChaCha20Cipher.this.initialized) {
                if (!ChaCha20Cipher.this.aadDone) {
                    ChaCha20Cipher.this.authPad16(ChaCha20Cipher.this.aadLen);
                    ChaCha20Cipher.this.aadDone = true;
                }
                try {
                    if (out != null) {
                        ChaCha20Cipher.this.checkFromIndexSize(outOff, inLen, out.length);
                        if (in != null) {
                            ChaCha20Cipher.this.checkFromIndexSize(inOff, inLen, in.length);
                            ChaCha20Cipher.this.chaCha20Transform(in, inOff, inLen, out, outOff);
                            ChaCha20Cipher.this.dataLen += ChaCha20Cipher.this.authUpdate(out, outOff, inLen);
                        }
                        return inLen;
                    }
                    throw new ShortBufferException("Output buffer too small");
                } catch (IndexOutOfBoundsException e) {
                    throw new ShortBufferException("Output buffer too small");
                }
            }
            throw new IllegalStateException("Must use either a different key or iv.");
        }

        @Override // org.openjsse.com.sun.crypto.provider.ChaCha20Cipher.ChaChaEngine
        public int doFinal(byte[] in, int inOff, int inLen, byte[] out, int outOff) throws ShortBufferException, KeyException {
            if (inLen + 16 > out.length - outOff) {
                throw new ShortBufferException("Output buffer too small");
            }
            doUpdate(in, inOff, inLen, out, outOff);
            ChaCha20Cipher.this.authFinalizeData(null, 0, 0, out, outOff + inLen);
            ChaCha20Cipher.this.aadDone = false;
            return inLen + 16;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/ChaCha20Cipher$EngineAEADDec.class */
    public final class EngineAEADDec implements ChaChaEngine {
        private final ByteArrayOutputStream cipherBuf;
        private final byte[] tag;

        @Override // org.openjsse.com.sun.crypto.provider.ChaCha20Cipher.ChaChaEngine
        public int getOutputSize(int inLen, boolean isFinal) {
            if (isFinal) {
                return Integer.max(Math.addExact(inLen - 16, this.cipherBuf.size()), 0);
            }
            return 0;
        }

        private EngineAEADDec() throws InvalidKeyException {
            ChaCha20Cipher.this.initAuthenticator();
            ChaCha20Cipher.this.counter = 1L;
            this.cipherBuf = new ByteArrayOutputStream(1024);
            this.tag = new byte[16];
        }

        @Override // org.openjsse.com.sun.crypto.provider.ChaCha20Cipher.ChaChaEngine
        public int doUpdate(byte[] in, int inOff, int inLen, byte[] out, int outOff) {
            if (ChaCha20Cipher.this.initialized) {
                if (!ChaCha20Cipher.this.aadDone) {
                    ChaCha20Cipher.this.authPad16(ChaCha20Cipher.this.aadLen);
                    ChaCha20Cipher.this.aadDone = true;
                }
                if (in != null) {
                    ChaCha20Cipher.this.checkFromIndexSize(inOff, inLen, in.length);
                    this.cipherBuf.write(in, inOff, inLen);
                    return 0;
                }
                return 0;
            }
            throw new IllegalStateException("Must use either a different key or iv.");
        }

        @Override // org.openjsse.com.sun.crypto.provider.ChaCha20Cipher.ChaChaEngine
        public int doFinal(byte[] in, int inOff, int inLen, byte[] out, int outOff) throws ShortBufferException, AEADBadTagException, KeyException {
            byte[] ctPlusTag;
            int ctPlusTagLen;
            if (this.cipherBuf.size() == 0 && inOff == 0) {
                doUpdate(null, inOff, inLen, out, outOff);
                ctPlusTag = in;
                ctPlusTagLen = inLen;
            } else {
                doUpdate(in, inOff, inLen, out, outOff);
                ctPlusTag = this.cipherBuf.toByteArray();
                ctPlusTagLen = ctPlusTag.length;
            }
            this.cipherBuf.reset();
            if (ctPlusTagLen < 16) {
                throw new AEADBadTagException("Input too short - need tag");
            }
            int ctLen = ctPlusTagLen - 16;
            try {
                ChaCha20Cipher.this.checkFromIndexSize(outOff, ctLen, out.length);
                ChaCha20Cipher.this.authFinalizeData(ctPlusTag, 0, ctLen, this.tag, 0);
                ByteBuffer bb = ByteBuffer.allocate(32);
                bb.order(ByteOrder.nativeOrder());
                bb.put(ctPlusTag, ctLen, 16);
                bb.put(this.tag, 0, 16);
                long tagCompare = (bb.getLong(0) ^ bb.getLong(16)) | (bb.getLong(8) ^ bb.getLong(24));
                if (tagCompare == 0) {
                    ChaCha20Cipher.this.chaCha20Transform(ctPlusTag, 0, ctLen, out, outOff);
                    ChaCha20Cipher.this.aadDone = false;
                    return ctLen;
                }
                throw new AEADBadTagException("Tag mismatch");
            } catch (IndexOutOfBoundsException e) {
                throw new ShortBufferException("Output buffer too small");
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/ChaCha20Cipher$ChaCha20Only.class */
    public static final class ChaCha20Only extends ChaCha20Cipher {
        public ChaCha20Only() {
            this.mode = 0;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/ChaCha20Cipher$ChaCha20Poly1305.class */
    public static final class ChaCha20Poly1305 extends ChaCha20Cipher {
        public ChaCha20Poly1305() {
            this.mode = 1;
            this.authAlgName = "Poly1305";
        }
    }
}