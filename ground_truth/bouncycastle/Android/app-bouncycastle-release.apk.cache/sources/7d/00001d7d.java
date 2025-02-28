package org.bouncycastle.crypto.engines;

import kotlin.UByte;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/* loaded from: classes2.dex */
public class VMPCEngine implements StreamCipher {
    protected byte[] workingIV;
    protected byte[] workingKey;

    /* renamed from: n */
    protected byte f701n = 0;

    /* renamed from: P */
    protected byte[] f700P = null;

    /* renamed from: s */
    protected byte f702s = 0;

    @Override // org.bouncycastle.crypto.StreamCipher
    public String getAlgorithmName() {
        return "VMPC";
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        if (!(cipherParameters instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("VMPC init parameters must include an IV");
        }
        ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
        if (!(parametersWithIV.getParameters() instanceof KeyParameter)) {
            throw new IllegalArgumentException("VMPC init parameters must include a key");
        }
        KeyParameter keyParameter = (KeyParameter) parametersWithIV.getParameters();
        byte[] iv = parametersWithIV.getIV();
        this.workingIV = iv;
        if (iv == null || iv.length < 1 || iv.length > 768) {
            throw new IllegalArgumentException("VMPC requires 1 to 768 bytes of IV");
        }
        byte[] key = keyParameter.getKey();
        this.workingKey = key;
        initKey(key, this.workingIV);
        String algorithmName = getAlgorithmName();
        byte[] bArr = this.workingKey;
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(algorithmName, bArr.length >= 32 ? 256 : bArr.length * 8, cipherParameters, Utils.getPurpose(z)));
    }

    protected void initKey(byte[] bArr, byte[] bArr2) {
        this.f702s = (byte) 0;
        this.f700P = new byte[256];
        for (int i = 0; i < 256; i++) {
            this.f700P[i] = (byte) i;
        }
        for (int i2 = 0; i2 < 768; i2++) {
            byte[] bArr3 = this.f700P;
            byte b = this.f702s;
            int i3 = i2 & 255;
            byte b2 = bArr3[i3];
            byte b3 = bArr3[(b + b2 + bArr[i2 % bArr.length]) & 255];
            this.f702s = b3;
            bArr3[i3] = bArr3[b3 & UByte.MAX_VALUE];
            bArr3[b3 & UByte.MAX_VALUE] = b2;
        }
        for (int i4 = 0; i4 < 768; i4++) {
            byte[] bArr4 = this.f700P;
            byte b4 = this.f702s;
            int i5 = i4 & 255;
            byte b5 = bArr4[i5];
            byte b6 = bArr4[(b4 + b5 + bArr2[i4 % bArr2.length]) & 255];
            this.f702s = b6;
            bArr4[i5] = bArr4[b6 & UByte.MAX_VALUE];
            bArr4[b6 & UByte.MAX_VALUE] = b5;
        }
        this.f701n = (byte) 0;
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) {
        if (i + i2 <= bArr.length) {
            if (i3 + i2 <= bArr2.length) {
                for (int i4 = 0; i4 < i2; i4++) {
                    byte[] bArr3 = this.f700P;
                    byte b = this.f702s;
                    byte b2 = this.f701n;
                    byte b3 = bArr3[(b + bArr3[b2 & UByte.MAX_VALUE]) & 255];
                    this.f702s = b3;
                    byte b4 = bArr3[(bArr3[bArr3[b3 & UByte.MAX_VALUE] & UByte.MAX_VALUE] + 1) & 255];
                    byte b5 = bArr3[b2 & UByte.MAX_VALUE];
                    bArr3[b2 & UByte.MAX_VALUE] = bArr3[b3 & UByte.MAX_VALUE];
                    bArr3[b3 & UByte.MAX_VALUE] = b5;
                    this.f701n = (byte) ((b2 + 1) & 255);
                    bArr2[i4 + i3] = (byte) (bArr[i4 + i] ^ b4);
                }
                return i2;
            }
            throw new OutputLengthException("output buffer too short");
        }
        throw new DataLengthException("input buffer too short");
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public void reset() {
        initKey(this.workingKey, this.workingIV);
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public byte returnByte(byte b) {
        byte[] bArr = this.f700P;
        byte b2 = this.f702s;
        byte b3 = this.f701n;
        byte b4 = bArr[(b2 + bArr[b3 & UByte.MAX_VALUE]) & 255];
        this.f702s = b4;
        byte b5 = bArr[(bArr[bArr[b4 & UByte.MAX_VALUE] & UByte.MAX_VALUE] + 1) & 255];
        byte b6 = bArr[b3 & UByte.MAX_VALUE];
        bArr[b3 & UByte.MAX_VALUE] = bArr[b4 & UByte.MAX_VALUE];
        bArr[b4 & UByte.MAX_VALUE] = b6;
        this.f701n = (byte) ((b3 + 1) & 255);
        return (byte) (b ^ b5);
    }
}