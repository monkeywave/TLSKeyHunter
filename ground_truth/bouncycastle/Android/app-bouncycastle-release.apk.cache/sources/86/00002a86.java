package org.bouncycastle.pqc.crypto.slhdsa;

import java.io.IOException;
import java.security.SecureRandom;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.DigestUtils;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class HashSLHDSASigner implements Signer {
    private Digest digest;
    private byte[] msgPrefix;
    private SLHDSAPrivateKeyParameters privKey;
    private SLHDSAPublicKeyParameters pubKey;
    private SecureRandom random;

    private static Digest createDigest(SLHDSAParameters sLHDSAParameters) {
        int type = sLHDSAParameters.getType();
        if (type == 0) {
            return sLHDSAParameters.getName().startsWith("sha2") ? (SLHDSAParameters.sha2_128f == sLHDSAParameters || SLHDSAParameters.sha2_128s == sLHDSAParameters) ? SHA256Digest.newInstance() : new SHA512Digest() : (SLHDSAParameters.shake_128f == sLHDSAParameters || SLHDSAParameters.shake_128s == sLHDSAParameters) ? new SHAKEDigest(128) : new SHAKEDigest(256);
        } else if (type != 1) {
            if (type != 2) {
                if (type != 3) {
                    if (type == 4) {
                        return new SHAKEDigest(256);
                    }
                    throw new IllegalArgumentException("unknown parameters type");
                }
                return new SHAKEDigest(128);
            }
            return new SHA512Digest();
        } else {
            return SHA256Digest.newInstance();
        }
    }

    private void initDigest(SLHDSAParameters sLHDSAParameters, ParametersWithContext parametersWithContext) {
        Digest createDigest = createDigest(sLHDSAParameters);
        this.digest = createDigest;
        try {
            byte[] encoded = DigestUtils.getDigestOid(createDigest.getAlgorithmName()).getEncoded(ASN1Encoding.DER);
            int contextLength = parametersWithContext == null ? 0 : parametersWithContext.getContextLength();
            int i = contextLength + 2;
            byte[] bArr = new byte[encoded.length + i];
            this.msgPrefix = bArr;
            bArr[0] = 1;
            bArr[1] = (byte) contextLength;
            if (parametersWithContext != null) {
                parametersWithContext.copyContextTo(bArr, 2, contextLength);
            }
            System.arraycopy(encoded, 0, this.msgPrefix, i, encoded.length);
        } catch (IOException e) {
            throw new IllegalStateException("oid encoding failed: " + e.getMessage());
        }
    }

    private static byte[] internalGenerateSignature(SLHDSAPrivateKeyParameters sLHDSAPrivateKeyParameters, byte[] bArr, byte[] bArr2, byte[] bArr3) {
        SLHDSAEngine engine = sLHDSAPrivateKeyParameters.getParameters().getEngine();
        engine.init(sLHDSAPrivateKeyParameters.f1419pk.seed);
        Fors fors = new Fors(engine);
        byte[] PRF_msg = engine.PRF_msg(sLHDSAPrivateKeyParameters.f1420sk.prf, bArr3, bArr, bArr2);
        IndexedDigest H_msg = engine.H_msg(PRF_msg, sLHDSAPrivateKeyParameters.f1419pk.seed, sLHDSAPrivateKeyParameters.f1419pk.root, bArr, bArr2);
        byte[] bArr4 = H_msg.digest;
        long j = H_msg.idx_tree;
        int i = H_msg.idx_leaf;
        ADRS adrs = new ADRS();
        adrs.setTypeAndClear(3);
        adrs.setTreeAddress(j);
        adrs.setKeyPairAddress(i);
        SIG_FORS[] sign = fors.sign(bArr4, sLHDSAPrivateKeyParameters.f1420sk.seed, sLHDSAPrivateKeyParameters.f1419pk.seed, adrs);
        ADRS adrs2 = new ADRS();
        adrs2.setTypeAndClear(3);
        adrs2.setTreeAddress(j);
        adrs2.setKeyPairAddress(i);
        byte[] pkFromSig = fors.pkFromSig(sign, bArr4, sLHDSAPrivateKeyParameters.f1419pk.seed, adrs2);
        new ADRS().setTypeAndClear(2);
        byte[] sign2 = new C1399HT(engine, sLHDSAPrivateKeyParameters.getSeed(), sLHDSAPrivateKeyParameters.getPublicSeed()).sign(pkFromSig, j, i);
        int length = sign.length;
        byte[][] bArr5 = new byte[length + 2];
        int i2 = 0;
        bArr5[0] = PRF_msg;
        while (i2 != sign.length) {
            int i3 = i2 + 1;
            bArr5[i3] = Arrays.concatenate(sign[i2].f1399sk, Arrays.concatenate(sign[i2].authPath));
            i2 = i3;
        }
        bArr5[length + 1] = sign2;
        return Arrays.concatenate(bArr5);
    }

    private static boolean internalVerifySignature(SLHDSAPublicKeyParameters sLHDSAPublicKeyParameters, byte[] bArr, byte[] bArr2, byte[] bArr3) {
        SLHDSAEngine engine = sLHDSAPublicKeyParameters.getParameters().getEngine();
        engine.init(sLHDSAPublicKeyParameters.getSeed());
        ADRS adrs = new ADRS();
        if (((engine.f1403K * (engine.f1400A + 1)) + 1 + engine.f1402H + (engine.f1401D * engine.WOTS_LEN)) * engine.f1404N != bArr3.length) {
            return false;
        }
        SIG sig = new SIG(engine.f1404N, engine.f1403K, engine.f1400A, engine.f1401D, engine.H_PRIME, engine.WOTS_LEN, bArr3);
        byte[] r = sig.getR();
        SIG_FORS[] sig_fors = sig.getSIG_FORS();
        SIG_XMSS[] sig_ht = sig.getSIG_HT();
        IndexedDigest H_msg = engine.H_msg(r, sLHDSAPublicKeyParameters.getSeed(), sLHDSAPublicKeyParameters.getRoot(), bArr, bArr2);
        byte[] bArr4 = H_msg.digest;
        long j = H_msg.idx_tree;
        int i = H_msg.idx_leaf;
        adrs.setTypeAndClear(3);
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(j);
        adrs.setKeyPairAddress(i);
        byte[] pkFromSig = new Fors(engine).pkFromSig(sig_fors, bArr4, sLHDSAPublicKeyParameters.getSeed(), adrs);
        adrs.setTypeAndClear(2);
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(j);
        adrs.setKeyPairAddress(i);
        return new C1399HT(engine, null, sLHDSAPublicKeyParameters.getSeed()).verify(pkFromSig, sig_ht, sLHDSAPublicKeyParameters.getSeed(), j, i, sLHDSAPublicKeyParameters.getRoot());
    }

    @Override // org.bouncycastle.crypto.Signer
    public byte[] generateSignature() throws CryptoException, DataLengthException {
        SLHDSAEngine engine = this.privKey.getParameters().getEngine();
        engine.init(this.privKey.f1419pk.seed);
        byte[] bArr = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(bArr, 0);
        int i = engine.f1404N;
        byte[] bArr2 = new byte[i];
        SecureRandom secureRandom = this.random;
        if (secureRandom != null) {
            secureRandom.nextBytes(bArr2);
        } else {
            System.arraycopy(this.privKey.f1419pk.seed, 0, bArr2, 0, i);
        }
        return internalGenerateSignature(this.privKey, this.msgPrefix, bArr, bArr2);
    }

    @Override // org.bouncycastle.crypto.Signer
    public void init(boolean z, CipherParameters cipherParameters) {
        ParametersWithContext parametersWithContext;
        SLHDSAParameters parameters;
        if (cipherParameters instanceof ParametersWithContext) {
            ParametersWithContext parametersWithContext2 = (ParametersWithContext) cipherParameters;
            CipherParameters parameters2 = parametersWithContext2.getParameters();
            if (parametersWithContext2.getContextLength() > 255) {
                throw new IllegalArgumentException("context too long");
            }
            parametersWithContext = parametersWithContext2;
            cipherParameters = parameters2;
        } else {
            parametersWithContext = null;
        }
        if (z) {
            this.pubKey = null;
            if (cipherParameters instanceof ParametersWithRandom) {
                ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
                this.privKey = (SLHDSAPrivateKeyParameters) parametersWithRandom.getParameters();
                this.random = parametersWithRandom.getRandom();
            } else {
                this.privKey = (SLHDSAPrivateKeyParameters) cipherParameters;
                this.random = null;
            }
            parameters = this.privKey.getParameters();
        } else {
            SLHDSAPublicKeyParameters sLHDSAPublicKeyParameters = (SLHDSAPublicKeyParameters) cipherParameters;
            this.pubKey = sLHDSAPublicKeyParameters;
            this.privKey = null;
            this.random = null;
            parameters = sLHDSAPublicKeyParameters.getParameters();
        }
        initDigest(parameters, parametersWithContext);
    }

    protected byte[] internalGenerateSignature(byte[] bArr, byte[] bArr2) {
        return internalGenerateSignature(this.privKey, null, bArr, bArr2);
    }

    protected boolean internalVerifySignature(byte[] bArr, byte[] bArr2) {
        return internalVerifySignature(this.pubKey, null, bArr, bArr2);
    }

    @Override // org.bouncycastle.crypto.Signer
    public void reset() {
        this.digest.reset();
    }

    @Override // org.bouncycastle.crypto.Signer
    public void update(byte b) {
        this.digest.update(b);
    }

    @Override // org.bouncycastle.crypto.Signer
    public void update(byte[] bArr, int i, int i2) {
        this.digest.update(bArr, i, i2);
    }

    @Override // org.bouncycastle.crypto.Signer
    public boolean verifySignature(byte[] bArr) {
        byte[] bArr2 = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(bArr2, 0);
        return internalVerifySignature(this.pubKey, this.msgPrefix, bArr2, bArr);
    }
}