package org.bouncycastle.crypto.prng.drbg;

import java.util.Hashtable;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/prng/drbg/HashSP800DRBG.class */
public class HashSP800DRBG implements SP80090DRBG {
    private static final long RESEED_MAX = 140737488355328L;
    private static final int MAX_BITS_REQUEST = 262144;
    private Digest _digest;

    /* renamed from: _V */
    private byte[] f581_V;

    /* renamed from: _C */
    private byte[] f582_C;
    private long _reseedCounter;
    private EntropySource _entropySource;
    private int _securityStrength;
    private int _seedLength;
    private static final byte[] ONE = {1};
    private static final Hashtable seedlens = new Hashtable();

    public HashSP800DRBG(Digest digest, int i, EntropySource entropySource, byte[] bArr, byte[] bArr2) {
        if (i > Utils.getMaxSecurityStrength(digest)) {
            throw new IllegalArgumentException("Requested security strength is not supported by the derivation function");
        }
        if (entropySource.entropySize() < i) {
            throw new IllegalArgumentException("Not enough entropy for security strength required");
        }
        this._digest = digest;
        this._entropySource = entropySource;
        this._securityStrength = i;
        this._seedLength = ((Integer) seedlens.get(digest.getAlgorithmName())).intValue();
        this.f581_V = Utils.hash_df(this._digest, Arrays.concatenate(getEntropy(), bArr2, bArr), this._seedLength);
        byte[] bArr3 = new byte[this.f581_V.length + 1];
        System.arraycopy(this.f581_V, 0, bArr3, 1, this.f581_V.length);
        this.f582_C = Utils.hash_df(this._digest, bArr3, this._seedLength);
        this._reseedCounter = 1L;
    }

    @Override // org.bouncycastle.crypto.prng.drbg.SP80090DRBG
    public int getBlockSize() {
        return this._digest.getDigestSize() * 8;
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
            byte[] bArr3 = new byte[1 + this.f581_V.length + bArr2.length];
            bArr3[0] = 2;
            System.arraycopy(this.f581_V, 0, bArr3, 1, this.f581_V.length);
            System.arraycopy(bArr2, 0, bArr3, 1 + this.f581_V.length, bArr2.length);
            addTo(this.f581_V, hash(bArr3));
        }
        byte[] hashgen = hashgen(this.f581_V, length);
        byte[] bArr4 = new byte[this.f581_V.length + 1];
        System.arraycopy(this.f581_V, 0, bArr4, 1, this.f581_V.length);
        bArr4[0] = 3;
        addTo(this.f581_V, hash(bArr4));
        addTo(this.f581_V, this.f582_C);
        addTo(this.f581_V, new byte[]{(byte) (this._reseedCounter >> 24), (byte) (this._reseedCounter >> 16), (byte) (this._reseedCounter >> 8), (byte) this._reseedCounter});
        this._reseedCounter++;
        System.arraycopy(hashgen, 0, bArr, 0, bArr.length);
        return length;
    }

    private byte[] getEntropy() {
        byte[] entropy = this._entropySource.getEntropy();
        if (entropy.length < (this._securityStrength + 7) / 8) {
            throw new IllegalStateException("Insufficient entropy provided by entropy source");
        }
        return entropy;
    }

    private void addTo(byte[] bArr, byte[] bArr2) {
        int i = 0;
        for (int i2 = 1; i2 <= bArr2.length; i2++) {
            int i3 = (bArr[bArr.length - i2] & 255) + (bArr2[bArr2.length - i2] & 255) + i;
            i = i3 > 255 ? 1 : 0;
            bArr[bArr.length - i2] = (byte) i3;
        }
        for (int length = bArr2.length + 1; length <= bArr.length; length++) {
            int i4 = (bArr[bArr.length - length] & 255) + i;
            i = i4 > 255 ? 1 : 0;
            bArr[bArr.length - length] = (byte) i4;
        }
    }

    @Override // org.bouncycastle.crypto.prng.drbg.SP80090DRBG
    public void reseed(byte[] bArr) {
        this.f581_V = Utils.hash_df(this._digest, Arrays.concatenate(ONE, this.f581_V, getEntropy(), bArr), this._seedLength);
        byte[] bArr2 = new byte[this.f581_V.length + 1];
        bArr2[0] = 0;
        System.arraycopy(this.f581_V, 0, bArr2, 1, this.f581_V.length);
        this.f582_C = Utils.hash_df(this._digest, bArr2, this._seedLength);
        this._reseedCounter = 1L;
    }

    private byte[] hash(byte[] bArr) {
        byte[] bArr2 = new byte[this._digest.getDigestSize()];
        doHash(bArr, bArr2);
        return bArr2;
    }

    private void doHash(byte[] bArr, byte[] bArr2) {
        this._digest.update(bArr, 0, bArr.length);
        this._digest.doFinal(bArr2, 0);
    }

    private byte[] hashgen(byte[] bArr, int i) {
        int digestSize = (i / 8) / this._digest.getDigestSize();
        byte[] bArr2 = new byte[bArr.length];
        System.arraycopy(bArr, 0, bArr2, 0, bArr.length);
        byte[] bArr3 = new byte[i / 8];
        byte[] bArr4 = new byte[this._digest.getDigestSize()];
        for (int i2 = 0; i2 <= digestSize; i2++) {
            doHash(bArr2, bArr4);
            System.arraycopy(bArr4, 0, bArr3, i2 * bArr4.length, bArr3.length - (i2 * bArr4.length) > bArr4.length ? bArr4.length : bArr3.length - (i2 * bArr4.length));
            addTo(bArr2, ONE);
        }
        return bArr3;
    }

    static {
        seedlens.put(McElieceCCA2KeyGenParameterSpec.SHA1, Integers.valueOf(440));
        seedlens.put(McElieceCCA2KeyGenParameterSpec.SHA224, Integers.valueOf(440));
        seedlens.put("SHA-256", Integers.valueOf(440));
        seedlens.put(SPHINCSKeyParameters.SHA512_256, Integers.valueOf(440));
        seedlens.put("SHA-512/224", Integers.valueOf(440));
        seedlens.put(McElieceCCA2KeyGenParameterSpec.SHA384, Integers.valueOf(888));
        seedlens.put("SHA-512", Integers.valueOf(888));
    }
}