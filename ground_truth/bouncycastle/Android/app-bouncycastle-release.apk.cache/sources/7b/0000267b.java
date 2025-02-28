package org.bouncycastle.jsse.provider;

import org.bouncycastle.jsse.BCSNIServerName;

/* loaded from: classes2.dex */
class JsseSessionParameters {
    private final String endpointIDAlgorithm;
    private final BCSNIServerName matchedSNIServerName;

    /* JADX INFO: Access modifiers changed from: package-private */
    public JsseSessionParameters(String str, BCSNIServerName bCSNIServerName) {
        this.endpointIDAlgorithm = str;
        this.matchedSNIServerName = bCSNIServerName;
    }

    public String getEndpointIDAlgorithm() {
        return this.endpointIDAlgorithm;
    }

    public BCSNIServerName getMatchedSNIServerName() {
        return this.matchedSNIServerName;
    }
}