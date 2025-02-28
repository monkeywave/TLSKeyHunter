package org.bouncycastle.crypto.p004ec;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.p010ec.ECAlgorithms;
import org.bouncycastle.math.p010ec.ECMultiplier;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.math.p010ec.FixedPointCombMultiplier;

/* renamed from: org.bouncycastle.crypto.ec.ECFixedTransform */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/ec/ECFixedTransform.class */
public class ECFixedTransform implements ECPairFactorTransform {
    private ECPublicKeyParameters key;

    /* renamed from: k */
    private BigInteger f274k;

    public ECFixedTransform(BigInteger bigInteger) {
        this.f274k = bigInteger;
    }

    @Override // org.bouncycastle.crypto.p004ec.ECPairTransform
    public void init(CipherParameters cipherParameters) {
        if (!(cipherParameters instanceof ECPublicKeyParameters)) {
            throw new IllegalArgumentException("ECPublicKeyParameters are required for fixed transform.");
        }
        this.key = (ECPublicKeyParameters) cipherParameters;
    }

    @Override // org.bouncycastle.crypto.p004ec.ECPairTransform
    public ECPair transform(ECPair eCPair) {
        if (this.key == null) {
            throw new IllegalStateException("ECFixedTransform not initialised");
        }
        ECDomainParameters parameters = this.key.getParameters();
        BigInteger n = parameters.getN();
        ECMultiplier createBasePointMultiplier = createBasePointMultiplier();
        BigInteger mod = this.f274k.mod(n);
        ECPoint[] eCPointArr = {createBasePointMultiplier.multiply(parameters.getG(), mod).add(ECAlgorithms.cleanPoint(parameters.getCurve(), eCPair.getX())), this.key.getQ().multiply(mod).add(ECAlgorithms.cleanPoint(parameters.getCurve(), eCPair.getY()))};
        parameters.getCurve().normalizeAll(eCPointArr);
        return new ECPair(eCPointArr[0], eCPointArr[1]);
    }

    @Override // org.bouncycastle.crypto.p004ec.ECPairFactorTransform
    public BigInteger getTransformValue() {
        return this.f274k;
    }

    protected ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }
}