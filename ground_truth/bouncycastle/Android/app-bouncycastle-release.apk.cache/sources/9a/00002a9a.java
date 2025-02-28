package org.bouncycastle.pqc.crypto.slhdsa;

import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class SLHDSASigner implements MessageSigner {
    private static final byte[] DEFAULT_PREFIX = {0, 0};
    private byte[] msgPrefix;
    private SLHDSAPrivateKeyParameters privKey;
    private SLHDSAPublicKeyParameters pubKey;
    private SecureRandom random;

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

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] bArr) {
        SLHDSAEngine engine = this.privKey.getParameters().getEngine();
        engine.init(this.privKey.f1419pk.seed);
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

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public void init(boolean z, CipherParameters cipherParameters) {
        SLHDSAParameters parameters;
        if (cipherParameters instanceof ParametersWithContext) {
            ParametersWithContext parametersWithContext = (ParametersWithContext) cipherParameters;
            CipherParameters parameters2 = parametersWithContext.getParameters();
            int contextLength = parametersWithContext.getContextLength();
            if (contextLength > 255) {
                throw new IllegalArgumentException("context too long");
            }
            byte[] bArr = new byte[contextLength + 2];
            this.msgPrefix = bArr;
            bArr[0] = 0;
            bArr[1] = (byte) contextLength;
            parametersWithContext.copyContextTo(bArr, 2, contextLength);
            cipherParameters = parameters2;
        } else {
            this.msgPrefix = DEFAULT_PREFIX;
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
        if (parameters.isPreHash()) {
            throw new IllegalArgumentException("\"pure\" slh-dsa must use non pre-hash parameters");
        }
    }

    protected byte[] internalGenerateSignature(byte[] bArr, byte[] bArr2) {
        return internalGenerateSignature(this.privKey, null, bArr, bArr2);
    }

    protected boolean internalVerifySignature(byte[] bArr, byte[] bArr2) {
        return internalVerifySignature(this.pubKey, null, bArr, bArr2);
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] bArr, byte[] bArr2) {
        return internalVerifySignature(this.pubKey, this.msgPrefix, bArr, bArr2);
    }
}