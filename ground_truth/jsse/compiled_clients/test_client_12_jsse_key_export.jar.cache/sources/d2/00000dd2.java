package org.bouncycastle.pqc.crypto.sphincsplus;

import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/sphincsplus/SPHINCSPlusSigner.class */
public class SPHINCSPlusSigner implements MessageSigner {
    private SPHINCSPlusPrivateKeyParameters privKey;
    private SPHINCSPlusPublicKeyParameters pubKey;
    private SecureRandom random;

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public void init(boolean z, CipherParameters cipherParameters) {
        if (!z) {
            this.pubKey = (SPHINCSPlusPublicKeyParameters) cipherParameters;
        } else if (!(cipherParameters instanceof ParametersWithRandom)) {
            this.privKey = (SPHINCSPlusPrivateKeyParameters) cipherParameters;
        } else {
            this.privKey = (SPHINCSPlusPrivateKeyParameters) ((ParametersWithRandom) cipherParameters).getParameters();
            this.random = ((ParametersWithRandom) cipherParameters).getRandom();
        }
    }

    /* JADX WARN: Type inference failed for: r0v36, types: [byte[], byte[][]] */
    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] bArr) {
        SPHINCSPlusEngine engine = this.privKey.getParameters().getEngine();
        byte[] bArr2 = new byte[engine.f912N];
        if (this.random != null) {
            this.random.nextBytes(bArr2);
        }
        Fors fors = new Fors(engine);
        byte[] PRF_msg = engine.PRF_msg(this.privKey.f918sk.prf, bArr2, bArr);
        IndexedDigest H_msg = engine.H_msg(PRF_msg, this.privKey.f919pk.seed, this.privKey.f919pk.root, bArr);
        byte[] bArr3 = H_msg.digest;
        long j = H_msg.idx_tree;
        int i = H_msg.idx_leaf;
        ADRS adrs = new ADRS();
        adrs.setType(3);
        adrs.setTreeAddress(j);
        adrs.setKeyPairAddress(i);
        SIG_FORS[] sign = fors.sign(bArr3, this.privKey.f918sk.seed, this.privKey.f919pk.seed, adrs);
        byte[] pkFromSig = fors.pkFromSig(sign, bArr3, this.privKey.f919pk.seed, adrs);
        new ADRS().setType(2);
        byte[] sign2 = new C0329HT(engine, this.privKey.getSeed(), this.privKey.getPublicSeed()).sign(pkFromSig, j, i);
        ?? r0 = new byte[sign.length + 2];
        r0[0] = PRF_msg;
        for (int i2 = 0; i2 != sign.length; i2++) {
            r0[1 + i2] = Arrays.concatenate(sign[i2].f911sk, Arrays.concatenate(sign[i2].authPath));
        }
        r0[r0.length - 1] = sign2;
        return Arrays.concatenate(r0);
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] bArr, byte[] bArr2) {
        SPHINCSPlusEngine engine = this.pubKey.getParameters().getEngine();
        ADRS adrs = new ADRS();
        SIG sig = new SIG(engine.f912N, engine.f915K, engine.f914A, engine.f913D, engine.H_PRIME, engine.WOTS_LEN, bArr2);
        byte[] r = sig.getR();
        SIG_FORS[] sig_fors = sig.getSIG_FORS();
        SIG_XMSS[] sig_ht = sig.getSIG_HT();
        IndexedDigest H_msg = engine.H_msg(r, this.pubKey.getSeed(), this.pubKey.getRoot(), bArr);
        byte[] bArr3 = H_msg.digest;
        long j = H_msg.idx_tree;
        int i = H_msg.idx_leaf;
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(j);
        adrs.setType(3);
        adrs.setKeyPairAddress(i);
        byte[] pkFromSig = new Fors(engine).pkFromSig(sig_fors, bArr3, this.pubKey.getSeed(), adrs);
        adrs.setType(2);
        return new C0329HT(engine, null, this.pubKey.getSeed()).verify(pkFromSig, sig_ht, this.pubKey.getSeed(), j, i, this.pubKey.getRoot());
    }
}