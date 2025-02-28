package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.WeakHashMap;
import javassist.bytecode.Opcode;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.p012io.Streams;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/lms/LMSPrivateKeyParameters.class */
public class LMSPrivateKeyParameters extends LMSKeyParameters implements LMSContextBasedSigner {

    /* renamed from: T1 */
    private static CacheKey f840T1 = new CacheKey(1);
    private static CacheKey[] internedKeys = new CacheKey[Opcode.LOR];

    /* renamed from: I */
    private final byte[] f841I;
    private final LMSigParameters parameters;
    private final LMOtsParameters otsParameters;
    private final int maxQ;
    private final byte[] masterSecret;
    private final Map<CacheKey, byte[]> tCache;
    private final int maxCacheR;
    private final Digest tDigest;

    /* renamed from: q */
    private int f842q;
    private LMSPublicKeyParameters publicKey;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/lms/LMSPrivateKeyParameters$CacheKey.class */
    public static class CacheKey {
        private final int index;

        CacheKey(int i) {
            this.index = i;
        }

        public int hashCode() {
            return this.index;
        }

        public boolean equals(Object obj) {
            return (obj instanceof CacheKey) && ((CacheKey) obj).index == this.index;
        }
    }

    public LMSPrivateKeyParameters(LMSigParameters lMSigParameters, LMOtsParameters lMOtsParameters, int i, byte[] bArr, int i2, byte[] bArr2) {
        super(true);
        this.parameters = lMSigParameters;
        this.otsParameters = lMOtsParameters;
        this.f842q = i;
        this.f841I = Arrays.clone(bArr);
        this.maxQ = i2;
        this.masterSecret = Arrays.clone(bArr2);
        this.maxCacheR = 1 << (this.parameters.getH() + 1);
        this.tCache = new WeakHashMap();
        this.tDigest = DigestUtil.getDigest(lMSigParameters.getDigestOID());
    }

    private LMSPrivateKeyParameters(LMSPrivateKeyParameters lMSPrivateKeyParameters, int i, int i2) {
        super(true);
        this.parameters = lMSPrivateKeyParameters.parameters;
        this.otsParameters = lMSPrivateKeyParameters.otsParameters;
        this.f842q = i;
        this.f841I = lMSPrivateKeyParameters.f841I;
        this.maxQ = i2;
        this.masterSecret = lMSPrivateKeyParameters.masterSecret;
        this.maxCacheR = 1 << this.parameters.getH();
        this.tCache = lMSPrivateKeyParameters.tCache;
        this.tDigest = DigestUtil.getDigest(this.parameters.getDigestOID());
        this.publicKey = lMSPrivateKeyParameters.publicKey;
    }

    public static LMSPrivateKeyParameters getInstance(byte[] bArr, byte[] bArr2) throws IOException {
        LMSPrivateKeyParameters lMSPrivateKeyParameters = getInstance(bArr);
        lMSPrivateKeyParameters.publicKey = LMSPublicKeyParameters.getInstance(bArr2);
        return lMSPrivateKeyParameters;
    }

    public static LMSPrivateKeyParameters getInstance(Object obj) throws IOException {
        if (obj instanceof LMSPrivateKeyParameters) {
            return (LMSPrivateKeyParameters) obj;
        }
        if (!(obj instanceof DataInputStream)) {
            if (!(obj instanceof byte[])) {
                if (obj instanceof InputStream) {
                    return getInstance(Streams.readAll((InputStream) obj));
                }
                throw new IllegalArgumentException("cannot parse " + obj);
            }
            DataInputStream dataInputStream = null;
            try {
                dataInputStream = new DataInputStream(new ByteArrayInputStream((byte[]) obj));
                LMSPrivateKeyParameters lMSPrivateKeyParameters = getInstance(dataInputStream);
                if (dataInputStream != null) {
                    dataInputStream.close();
                }
                return lMSPrivateKeyParameters;
            } catch (Throwable th) {
                if (dataInputStream != null) {
                    dataInputStream.close();
                }
                throw th;
            }
        }
        DataInputStream dataInputStream2 = (DataInputStream) obj;
        if (dataInputStream2.readInt() != 0) {
            throw new IllegalStateException("expected version 0 lms private key");
        }
        LMSigParameters parametersForType = LMSigParameters.getParametersForType(dataInputStream2.readInt());
        LMOtsParameters parametersForType2 = LMOtsParameters.getParametersForType(dataInputStream2.readInt());
        byte[] bArr = new byte[16];
        dataInputStream2.readFully(bArr);
        int readInt = dataInputStream2.readInt();
        int readInt2 = dataInputStream2.readInt();
        int readInt3 = dataInputStream2.readInt();
        if (readInt3 < 0) {
            throw new IllegalStateException("secret length less than zero");
        }
        if (readInt3 > dataInputStream2.available()) {
            throw new IOException("secret length exceeded " + dataInputStream2.available());
        }
        byte[] bArr2 = new byte[readInt3];
        dataInputStream2.readFully(bArr2);
        return new LMSPrivateKeyParameters(parametersForType, parametersForType2, readInt, bArr, readInt2, bArr2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMOtsPrivateKey getCurrentOTSKey() {
        LMOtsPrivateKey lMOtsPrivateKey;
        synchronized (this) {
            if (this.f842q >= this.maxQ) {
                throw new ExhaustedPrivateKeyException("ots private keys expired");
            }
            lMOtsPrivateKey = new LMOtsPrivateKey(this.otsParameters, this.f841I, this.f842q, this.masterSecret);
        }
        return lMOtsPrivateKey;
    }

    public synchronized int getIndex() {
        return this.f842q;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized void incIndex() {
        this.f842q++;
    }

    /* JADX WARN: Type inference failed for: r0v13, types: [byte[], byte[][]] */
    @Override // org.bouncycastle.pqc.crypto.lms.LMSContextBasedSigner
    public LMSContext generateLMSContext() {
        int h = getSigParameters().getH();
        int index = getIndex();
        LMOtsPrivateKey nextOtsPrivateKey = getNextOtsPrivateKey();
        int i = (1 << h) + index;
        ?? r0 = new byte[h];
        for (int i2 = 0; i2 < h; i2++) {
            r0[i2] = findT((i / (1 << i2)) ^ 1);
        }
        return nextOtsPrivateKey.getSignatureContext(getSigParameters(), r0);
    }

    @Override // org.bouncycastle.pqc.crypto.lms.LMSContextBasedSigner
    public byte[] generateSignature(LMSContext lMSContext) {
        try {
            return LMS.generateSign(lMSContext).getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("unable to encode signature: " + e.getMessage(), e);
        }
    }

    LMOtsPrivateKey getNextOtsPrivateKey() {
        LMOtsPrivateKey lMOtsPrivateKey;
        synchronized (this) {
            if (this.f842q >= this.maxQ) {
                throw new ExhaustedPrivateKeyException("ots private key exhausted");
            }
            lMOtsPrivateKey = new LMOtsPrivateKey(this.otsParameters, this.f841I, this.f842q, this.masterSecret);
            incIndex();
        }
        return lMOtsPrivateKey;
    }

    public LMSPrivateKeyParameters extractKeyShard(int i) {
        LMSPrivateKeyParameters lMSPrivateKeyParameters;
        synchronized (this) {
            if (this.f842q + i >= this.maxQ) {
                throw new IllegalArgumentException("usageCount exceeds usages remaining");
            }
            lMSPrivateKeyParameters = new LMSPrivateKeyParameters(this, this.f842q, this.f842q + i);
            this.f842q += i;
        }
        return lMSPrivateKeyParameters;
    }

    public LMSigParameters getSigParameters() {
        return this.parameters;
    }

    public LMOtsParameters getOtsParameters() {
        return this.otsParameters;
    }

    public byte[] getI() {
        return Arrays.clone(this.f841I);
    }

    public byte[] getMasterSecret() {
        return Arrays.clone(this.masterSecret);
    }

    @Override // org.bouncycastle.pqc.crypto.lms.LMSContextBasedSigner
    public long getUsagesRemaining() {
        return this.maxQ - this.f842q;
    }

    public LMSPublicKeyParameters getPublicKey() {
        LMSPublicKeyParameters lMSPublicKeyParameters;
        synchronized (this) {
            if (this.publicKey == null) {
                this.publicKey = new LMSPublicKeyParameters(this.parameters, this.otsParameters, findT(f840T1), this.f841I);
            }
            lMSPublicKeyParameters = this.publicKey;
        }
        return lMSPublicKeyParameters;
    }

    byte[] findT(int i) {
        if (i < this.maxCacheR) {
            return findT(i < internedKeys.length ? internedKeys[i] : new CacheKey(i));
        }
        return calcT(i);
    }

    private byte[] findT(CacheKey cacheKey) {
        synchronized (this.tCache) {
            byte[] bArr = this.tCache.get(cacheKey);
            if (bArr != null) {
                return bArr;
            }
            byte[] calcT = calcT(cacheKey.index);
            this.tCache.put(cacheKey, calcT);
            return calcT;
        }
    }

    private byte[] calcT(int i) {
        int h = 1 << getSigParameters().getH();
        if (i >= h) {
            LmsUtils.byteArray(getI(), this.tDigest);
            LmsUtils.u32str(i, this.tDigest);
            LmsUtils.u16str((short) -32126, this.tDigest);
            LmsUtils.byteArray(LM_OTS.lms_ots_generatePublicKey(getOtsParameters(), getI(), i - h, getMasterSecret()), this.tDigest);
            byte[] bArr = new byte[this.tDigest.getDigestSize()];
            this.tDigest.doFinal(bArr, 0);
            return bArr;
        }
        byte[] findT = findT(2 * i);
        byte[] findT2 = findT((2 * i) + 1);
        LmsUtils.byteArray(getI(), this.tDigest);
        LmsUtils.u32str(i, this.tDigest);
        LmsUtils.u16str((short) -31869, this.tDigest);
        LmsUtils.byteArray(findT, this.tDigest);
        LmsUtils.byteArray(findT2, this.tDigest);
        byte[] bArr2 = new byte[this.tDigest.getDigestSize()];
        this.tDigest.doFinal(bArr2, 0);
        return bArr2;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        LMSPrivateKeyParameters lMSPrivateKeyParameters = (LMSPrivateKeyParameters) obj;
        if (this.f842q == lMSPrivateKeyParameters.f842q && this.maxQ == lMSPrivateKeyParameters.maxQ && Arrays.areEqual(this.f841I, lMSPrivateKeyParameters.f841I)) {
            if (this.parameters != null) {
                if (!this.parameters.equals(lMSPrivateKeyParameters.parameters)) {
                    return false;
                }
            } else if (lMSPrivateKeyParameters.parameters != null) {
                return false;
            }
            if (this.otsParameters != null) {
                if (!this.otsParameters.equals(lMSPrivateKeyParameters.otsParameters)) {
                    return false;
                }
            } else if (lMSPrivateKeyParameters.otsParameters != null) {
                return false;
            }
            if (Arrays.areEqual(this.masterSecret, lMSPrivateKeyParameters.masterSecret)) {
                if (this.publicKey == null || lMSPrivateKeyParameters.publicKey == null) {
                    return true;
                }
                return this.publicKey.equals(lMSPrivateKeyParameters.publicKey);
            }
            return false;
        }
        return false;
    }

    public int hashCode() {
        return (31 * ((31 * ((31 * ((31 * ((31 * ((31 * this.f842q) + Arrays.hashCode(this.f841I))) + (this.parameters != null ? this.parameters.hashCode() : 0))) + (this.otsParameters != null ? this.otsParameters.hashCode() : 0))) + this.maxQ)) + Arrays.hashCode(this.masterSecret))) + (this.publicKey != null ? this.publicKey.hashCode() : 0);
    }

    @Override // org.bouncycastle.pqc.crypto.lms.LMSKeyParameters, org.bouncycastle.util.Encodable
    public byte[] getEncoded() throws IOException {
        return Composer.compose().u32str(0).u32str(this.parameters.getType()).u32str(this.otsParameters.getType()).bytes(this.f841I).u32str(this.f842q).u32str(this.maxQ).u32str(this.masterSecret.length).bytes(this.masterSecret).build();
    }

    static {
        internedKeys[1] = f840T1;
        for (int i = 2; i < internedKeys.length; i++) {
            internedKeys[i] = new CacheKey(i);
        }
    }
}