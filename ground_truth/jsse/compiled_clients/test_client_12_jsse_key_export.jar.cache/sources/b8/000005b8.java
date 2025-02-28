package org.bouncycastle.crypto.prng.drbg;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/prng/drbg/HMacSP800DRBG.class */
public class HMacSP800DRBG implements SP80090DRBG {
    private static final long RESEED_MAX = 140737488355328L;
    private static final int MAX_BITS_REQUEST = 262144;

    /* renamed from: _K */
    private byte[] f579_K;

    /* renamed from: _V */
    private byte[] f580_V;
    private long _reseedCounter;
    private EntropySource _entropySource;
    private Mac _hMac;
    private int _securityStrength;

    public HMacSP800DRBG(Mac mac, int i, EntropySource entropySource, byte[] bArr, byte[] bArr2) {
        if (i > Utils.getMaxSecurityStrength(mac)) {
            throw new IllegalArgumentException("Requested security strength is not supported by the derivation function");
        }
        if (entropySource.entropySize() < i) {
            throw new IllegalArgumentException("Not enough entropy for security strength required");
        }
        this._securityStrength = i;
        this._entropySource = entropySource;
        this._hMac = mac;
        byte[] concatenate = Arrays.concatenate(getEntropy(), bArr2, bArr);
        this.f579_K = new byte[mac.getMacSize()];
        this.f580_V = new byte[this.f579_K.length];
        Arrays.fill(this.f580_V, (byte) 1);
        hmac_DRBG_Update(concatenate);
        this._reseedCounter = 1L;
    }

    private void hmac_DRBG_Update(byte[] bArr) {
        hmac_DRBG_Update_Func(bArr, (byte) 0);
        if (bArr != null) {
            hmac_DRBG_Update_Func(bArr, (byte) 1);
        }
    }

    private void hmac_DRBG_Update_Func(byte[] bArr, byte b) {
        this._hMac.init(new KeyParameter(this.f579_K));
        this._hMac.update(this.f580_V, 0, this.f580_V.length);
        this._hMac.update(b);
        if (bArr != null) {
            this._hMac.update(bArr, 0, bArr.length);
        }
        this._hMac.doFinal(this.f579_K, 0);
        this._hMac.init(new KeyParameter(this.f579_K));
        this._hMac.update(this.f580_V, 0, this.f580_V.length);
        this._hMac.doFinal(this.f580_V, 0);
    }

    @Override // org.bouncycastle.crypto.prng.drbg.SP80090DRBG
    public int getBlockSize() {
        return this.f580_V.length * 8;
    }

    @Override // org.bouncycastle.crypto.prng.drbg.SP80090DRBG
    public int generate(byte[] bArr, byte[] bArr2, boolean z) {
        int length = bArr.length * 8;
        if (length > MAX_BITS_REQUEST) {
            throw new IllegalArgumentException("Number of bits per request limited to 262144");
        }
        if (this._reseedCounter > RESEED_MAX) {
            return -1;
        }
        if (z) {
            reseed(bArr2);
            bArr2 = null;
        }
        if (bArr2 != null) {
            hmac_DRBG_Update(bArr2);
        }
        byte[] bArr3 = new byte[bArr.length];
        int length2 = bArr.length / this.f580_V.length;
        this._hMac.init(new KeyParameter(this.f579_K));
        for (int i = 0; i < length2; i++) {
            this._hMac.update(this.f580_V, 0, this.f580_V.length);
            this._hMac.doFinal(this.f580_V, 0);
            System.arraycopy(this.f580_V, 0, bArr3, i * this.f580_V.length, this.f580_V.length);
        }
        if (length2 * this.f580_V.length < bArr3.length) {
            this._hMac.update(this.f580_V, 0, this.f580_V.length);
            this._hMac.doFinal(this.f580_V, 0);
            System.arraycopy(this.f580_V, 0, bArr3, length2 * this.f580_V.length, bArr3.length - (length2 * this.f580_V.length));
        }
        hmac_DRBG_Update(bArr2);
        this._reseedCounter++;
        System.arraycopy(bArr3, 0, bArr, 0, bArr.length);
        return length;
    }

    @Override // org.bouncycastle.crypto.prng.drbg.SP80090DRBG
    public void reseed(byte[] bArr) {
        hmac_DRBG_Update(Arrays.concatenate(getEntropy(), bArr));
        this._reseedCounter = 1L;
    }

    private byte[] getEntropy() {
        byte[] entropy = this._entropySource.getEntropy();
        if (entropy.length < (this._securityStrength + 7) / 8) {
            throw new IllegalStateException("Insufficient entropy provided by entropy source");
        }
        return entropy;
    }
}