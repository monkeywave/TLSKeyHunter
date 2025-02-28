package org.bouncycastle.jsse.provider;

import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.SSLEngine;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class ProvSSLEngine_8 extends ProvSSLEngine {
    /* JADX INFO: Access modifiers changed from: protected */
    public ProvSSLEngine_8(ContextData contextData) {
        super(contextData);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public ProvSSLEngine_8(ContextData contextData, String str, int i) {
        super(contextData, str, i);
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized BiFunction<SSLEngine, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return JsseUtils_8.exportAPSelector(this.sslParameters.getEngineAPSelector());
    }

    @Override // javax.net.ssl.SSLEngine
    public synchronized void setHandshakeApplicationProtocolSelector(BiFunction<SSLEngine, List<String>, String> biFunction) {
        this.sslParameters.setEngineAPSelector(JsseUtils_8.importAPSelector(biFunction));
    }
}