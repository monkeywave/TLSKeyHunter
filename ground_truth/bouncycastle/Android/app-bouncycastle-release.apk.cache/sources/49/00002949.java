package org.bouncycastle.pqc.crypto;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/* loaded from: classes2.dex */
public interface ExchangePairGenerator {
    ExchangePair generateExchange(AsymmetricKeyParameter asymmetricKeyParameter);
}