package org.bouncycastle.crypto.engines;

import androidx.core.app.FrameMetricsAggregator;
import com.google.android.material.internal.ViewUtils;
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
public class HC128Engine implements StreamCipher {
    private boolean initialised;

    /* renamed from: iv */
    private byte[] f629iv;
    private byte[] key;

    /* renamed from: p */
    private int[] f630p = new int[512];

    /* renamed from: q */
    private int[] f631q = new int[512];
    private int cnt = 0;
    private byte[] buf = new byte[4];
    private int idx = 0;

    private static int dim(int i, int i2) {
        return mod512(i - i2);
    }

    /* renamed from: f1 */
    private static int m70f1(int i) {
        return (i >>> 3) ^ (rotateRight(i, 7) ^ rotateRight(i, 18));
    }

    /* renamed from: f2 */
    private static int m69f2(int i) {
        return (i >>> 10) ^ (rotateRight(i, 17) ^ rotateRight(i, 19));
    }

    /* renamed from: g1 */
    private int m68g1(int i, int i2, int i3) {
        return (rotateRight(i, 10) ^ rotateRight(i3, 23)) + rotateRight(i2, 8);
    }

    /* renamed from: g2 */
    private int m67g2(int i, int i2, int i3) {
        return (rotateLeft(i, 10) ^ rotateLeft(i3, 23)) + rotateLeft(i2, 8);
    }

    private byte getByte() {
        if (this.idx == 0) {
            int step = step();
            byte[] bArr = this.buf;
            bArr[0] = (byte) (step & 255);
            bArr[1] = (byte) ((step >> 8) & 255);
            bArr[2] = (byte) ((step >> 16) & 255);
            bArr[3] = (byte) ((step >> 24) & 255);
        }
        byte[] bArr2 = this.buf;
        int i = this.idx;
        byte b = bArr2[i];
        this.idx = 3 & (i + 1);
        return b;
    }

    /* renamed from: h1 */
    private int m66h1(int i) {
        int[] iArr = this.f631q;
        return iArr[i & 255] + iArr[((i >> 16) & 255) + 256];
    }

    /* renamed from: h2 */
    private int m65h2(int i) {
        int[] iArr = this.f630p;
        return iArr[i & 255] + iArr[((i >> 16) & 255) + 256];
    }

    private void init() {
        if (this.key.length != 16) {
            throw new IllegalArgumentException("The key must be 128 bits long");
        }
        if (this.f629iv.length != 16) {
            throw new IllegalArgumentException("The IV must be 128 bits long");
        }
        this.idx = 0;
        this.cnt = 0;
        int[] iArr = new int[1280];
        for (int i = 0; i < 16; i++) {
            int i2 = i >> 2;
            iArr[i2] = ((this.key[i] & UByte.MAX_VALUE) << ((i & 3) * 8)) | iArr[i2];
        }
        System.arraycopy(iArr, 0, iArr, 4, 4);
        int i3 = 0;
        while (true) {
            byte[] bArr = this.f629iv;
            if (i3 >= bArr.length || i3 >= 16) {
                break;
            }
            int i4 = (i3 >> 2) + 8;
            iArr[i4] = ((bArr[i3] & UByte.MAX_VALUE) << ((i3 & 3) * 8)) | iArr[i4];
            i3++;
        }
        System.arraycopy(iArr, 8, iArr, 12, 4);
        for (int i5 = 16; i5 < 1280; i5++) {
            iArr[i5] = m69f2(iArr[i5 - 2]) + iArr[i5 - 7] + m70f1(iArr[i5 - 15]) + iArr[i5 - 16] + i5;
        }
        System.arraycopy(iArr, 256, this.f630p, 0, 512);
        System.arraycopy(iArr, ViewUtils.EDGE_TO_EDGE_FLAGS, this.f631q, 0, 512);
        for (int i6 = 0; i6 < 512; i6++) {
            this.f630p[i6] = step();
        }
        for (int i7 = 0; i7 < 512; i7++) {
            this.f631q[i7] = step();
        }
        this.cnt = 0;
    }

    private static int mod1024(int i) {
        return i & 1023;
    }

    private static int mod512(int i) {
        return i & FrameMetricsAggregator.EVERY_DURATION;
    }

    private static int rotateLeft(int i, int i2) {
        return (i >>> (-i2)) | (i << i2);
    }

    private static int rotateRight(int i, int i2) {
        return (i << (-i2)) | (i >>> i2);
    }

    private int step() {
        int m65h2;
        int i;
        int mod512 = mod512(this.cnt);
        if (this.cnt < 512) {
            int[] iArr = this.f630p;
            iArr[mod512] = iArr[mod512] + m68g1(iArr[dim(mod512, 3)], this.f630p[dim(mod512, 10)], this.f630p[dim(mod512, FrameMetricsAggregator.EVERY_DURATION)]);
            m65h2 = m66h1(this.f630p[dim(mod512, 12)]);
            i = this.f630p[mod512];
        } else {
            int[] iArr2 = this.f631q;
            iArr2[mod512] = iArr2[mod512] + m67g2(iArr2[dim(mod512, 3)], this.f631q[dim(mod512, 10)], this.f631q[dim(mod512, FrameMetricsAggregator.EVERY_DURATION)]);
            m65h2 = m65h2(this.f631q[dim(mod512, 12)]);
            i = this.f631q[mod512];
        }
        int i2 = i ^ m65h2;
        this.cnt = mod1024(this.cnt + 1);
        return i2;
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public String getAlgorithmName() {
        return "HC-128";
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        if (!(cipherParameters instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("no IV passed");
        }
        ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
        this.f629iv = parametersWithIV.getIV();
        CipherParameters parameters = parametersWithIV.getParameters();
        if (!(parameters instanceof KeyParameter)) {
            throw new IllegalArgumentException("Invalid parameter passed to HC128 init - " + cipherParameters.getClass().getName());
        }
        this.key = ((KeyParameter) parameters).getKey();
        init();
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(getAlgorithmName(), 128, cipherParameters, Utils.getPurpose(z)));
        this.initialised = true;
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws DataLengthException {
        if (this.initialised) {
            if (i + i2 <= bArr.length) {
                if (i3 + i2 <= bArr2.length) {
                    for (int i4 = 0; i4 < i2; i4++) {
                        bArr2[i3 + i4] = (byte) (bArr[i + i4] ^ getByte());
                    }
                    return i2;
                }
                throw new OutputLengthException("output buffer too short");
            }
            throw new DataLengthException("input buffer too short");
        }
        throw new IllegalStateException(getAlgorithmName() + " not initialised");
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public void reset() {
        init();
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public byte returnByte(byte b) {
        return (byte) (b ^ getByte());
    }
}