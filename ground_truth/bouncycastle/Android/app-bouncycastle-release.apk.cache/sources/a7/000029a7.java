package org.bouncycastle.pqc.crypto.gemss;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/* loaded from: classes2.dex */
public class GeMSSKeyParameters extends AsymmetricKeyParameter {
    final GeMSSParameters parameters;

    /* JADX INFO: Access modifiers changed from: protected */
    public GeMSSKeyParameters(boolean z, GeMSSParameters geMSSParameters) {
        super(z);
        this.parameters = geMSSParameters;
    }

    public GeMSSParameters getParameters() {
        return this.parameters;
    }
}