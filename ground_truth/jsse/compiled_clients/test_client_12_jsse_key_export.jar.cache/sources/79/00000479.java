package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.RC5Parameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/RC564Engine.class */
public class RC564Engine implements BlockCipher {
    private static final int wordSize = 64;
    private static final int bytesPerWord = 8;
    private int _noRounds = 12;

    /* renamed from: _S */
    private long[] f356_S = null;
    private static final long P64 = -5196783011329398165L;
    private static final long Q64 = -7046029254386353131L;
    private boolean forEncryption;

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return "RC5-64";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return 16;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        if (!(cipherParameters instanceof RC5Parameters)) {
            throw new IllegalArgumentException("invalid parameter passed to RC564 init - " + cipherParameters.getClass().getName());
        }
        RC5Parameters rC5Parameters = (RC5Parameters) cipherParameters;
        this.forEncryption = z;
        this._noRounds = rC5Parameters.getRounds();
        setKey(rC5Parameters.getKey());
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        return this.forEncryption ? encryptBlock(bArr, i, bArr2, i2) : decryptBlock(bArr, i, bArr2, i2);
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
    }

    /*  JADX ERROR: Method load error
        jadx.core.utils.exceptions.DecodeException: Load method exception: JavaClassParseException: Unknown opcode: 0x5e in method: org.bouncycastle.crypto.engines.RC564Engine.setKey(byte[]):void, file: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/RC564Engine.class
        	at jadx.core.dex.nodes.MethodNode.load(MethodNode.java:158)
        	at jadx.core.dex.nodes.ClassNode.load(ClassNode.java:409)
        	at jadx.core.ProcessClass.process(ProcessClass.java:67)
        	at jadx.core.ProcessClass.generateCode(ProcessClass.java:115)
        	at jadx.core.dex.nodes.ClassNode.decompile(ClassNode.java:383)
        	at jadx.core.dex.nodes.ClassNode.decompile(ClassNode.java:307)
        Caused by: jadx.plugins.input.java.utils.JavaClassParseException: Unknown opcode: 0x5e
        	at jadx.plugins.input.java.data.code.JavaCodeReader.visitInstructions(JavaCodeReader.java:71)
        	at jadx.core.dex.instructions.InsnDecoder.process(InsnDecoder.java:48)
        	at jadx.core.dex.nodes.MethodNode.load(MethodNode.java:148)
        	... 5 more
        */
    private void setKey(byte[] r1) {
        /*
        // Can't load method instructions: Load method exception: JavaClassParseException: Unknown opcode: 0x5e in method: org.bouncycastle.crypto.engines.RC564Engine.setKey(byte[]):void, file: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/RC564Engine.class
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.crypto.engines.RC564Engine.setKey(byte[]):void");
    }

    private int encryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        long bytesToWord = bytesToWord(bArr, i) + this.f356_S[0];
        long bytesToWord2 = bytesToWord(bArr, i + 8) + this.f356_S[1];
        for (int i3 = 1; i3 <= this._noRounds; i3++) {
            bytesToWord = rotateLeft(bytesToWord ^ bytesToWord2, bytesToWord2) + this.f356_S[2 * i3];
            bytesToWord2 = rotateLeft(bytesToWord2 ^ bytesToWord, bytesToWord) + this.f356_S[(2 * i3) + 1];
        }
        wordToBytes(bytesToWord, bArr2, i2);
        wordToBytes(bytesToWord2, bArr2, i2 + 8);
        return 16;
    }

    private int decryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        long bytesToWord = bytesToWord(bArr, i);
        long bytesToWord2 = bytesToWord(bArr, i + 8);
        for (int i3 = this._noRounds; i3 >= 1; i3--) {
            bytesToWord2 = rotateRight(bytesToWord2 - this.f356_S[(2 * i3) + 1], bytesToWord) ^ bytesToWord;
            bytesToWord = rotateRight(bytesToWord - this.f356_S[2 * i3], bytesToWord2) ^ bytesToWord2;
        }
        wordToBytes(bytesToWord - this.f356_S[0], bArr2, i2);
        wordToBytes(bytesToWord2 - this.f356_S[1], bArr2, i2 + 8);
        return 16;
    }

    private long rotateLeft(long j, long j2) {
        return (j << ((int) (j2 & 63))) | (j >>> ((int) (64 - (j2 & 63))));
    }

    private long rotateRight(long j, long j2) {
        return (j >>> ((int) (j2 & 63))) | (j << ((int) (64 - (j2 & 63))));
    }

    private long bytesToWord(byte[] bArr, int i) {
        long j = 0;
        for (int i2 = 7; i2 >= 0; i2--) {
            j = (j << 8) + (bArr[i2 + i] & 255);
        }
        return j;
    }

    private void wordToBytes(long j, byte[] bArr, int i) {
        for (int i2 = 0; i2 < 8; i2++) {
            bArr[i2 + i] = (byte) j;
            j >>>= 8;
        }
    }
}