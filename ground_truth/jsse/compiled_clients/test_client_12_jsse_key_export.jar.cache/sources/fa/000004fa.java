package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/AEADCipher.class */
public interface AEADCipher {
    void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException;

    String getAlgorithmName();

    void processAADByte(byte b);

    void processAADBytes(byte[] bArr, int i, int i2);

    int processByte(byte b, byte[] bArr, int i) throws DataLengthException;

    int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws DataLengthException;

    int doFinal(byte[] bArr, int i) throws IllegalStateException, InvalidCipherTextException;

    byte[] getMac();

    int getUpdateOutputSize(int i);

    int getOutputSize(int i);

    void reset();
}