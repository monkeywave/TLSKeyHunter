package org.bouncycastle.crypto.p010ec;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.p016ec.ECAlgorithms;
import org.bouncycastle.math.p016ec.ECMultiplier;
import org.bouncycastle.math.p016ec.ECPoint;
import org.bouncycastle.math.p016ec.FixedPointCombMultiplier;

/* renamed from: org.bouncycastle.crypto.ec.ECFixedTransform */
/* loaded from: classes2.dex */
public class ECFixedTransform implements ECPairFactorTransform {

    /* renamed from: k */
    private BigInteger f550k;
    private ECPublicKeyParameters key;

    public ECFixedTransform(BigInteger bigInteger) {
        this.f550k = bigInteger;
    }

    protected ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }

    @Override // org.bouncycastle.crypto.p010ec.ECPairFactorTransform
    public BigInteger getTransformValue() {
        return this.f550k;
    }

    @Override // org.bouncycastle.crypto.p010ec.ECPairTransform
    public void init(CipherParameters cipherParameters) {
        if (!(cipherParameters instanceof ECPublicKeyParameters)) {
            throw new IllegalArgumentException("ECPublicKeyParameters are required for fixed transform.");
        }
        this.key = (ECPublicKeyParameters) cipherParameters;
    }

    @Override // org.bouncycastle.crypto.p010ec.ECPairTransform
    public ECPair transform(ECPair eCPair) {
        ECPublicKeyParameters eCPublicKeyParameters = this.key;
        if (eCPublicKeyParameters != null) {
            ECDomainParameters parameters = eCPublicKeyParameters.getParameters();
            BigInteger n = parameters.getN();
            ECMultiplier createBasePointMultiplier = createBasePointMultiplier();
            BigInteger mod = this.f550k.mod(n);
            ECPoint[] eCPointArr = {createBasePointMultiplier.multiply(parameters.getG(), mod).add(ECAlgorithms.cleanPoint(parameters.getCurve(), eCPair.getX())), this.key.getQ().multiply(mod).add(ECAlgorithms.cleanPoint(parameters.getCurve(), eCPair.getY()))};
            parameters.getCurve().normalizeAll(eCPointArr);
            return new ECPair(eCPointArr[0], eCPointArr[1]);
        }
        throw new IllegalStateException("ECFixedTransform not initialised");
    }
}