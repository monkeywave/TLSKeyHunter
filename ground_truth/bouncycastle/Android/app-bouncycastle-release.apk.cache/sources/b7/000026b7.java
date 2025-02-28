package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.SSLSocket;

/* loaded from: classes2.dex */
class ProvSSLSocketWrap_8 extends ProvSSLSocketWrap {
    /* JADX INFO: Access modifiers changed from: protected */
    public ProvSSLSocketWrap_8(ContextData contextData, Socket socket, InputStream inputStream, boolean z) throws IOException {
        super(contextData, socket, inputStream, z);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public ProvSSLSocketWrap_8(ContextData contextData, Socket socket, String str, int i, boolean z) throws IOException {
        super(contextData, socket, str, i, z);
    }

    @Override // javax.net.ssl.SSLSocket
    public synchronized BiFunction<SSLSocket, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return JsseUtils_8.exportAPSelector(this.sslParameters.getSocketAPSelector());
    }

    @Override // javax.net.ssl.SSLSocket
    public synchronized void setHandshakeApplicationProtocolSelector(BiFunction<SSLSocket, List<String>, String> biFunction) {
        this.sslParameters.setSocketAPSelector(JsseUtils_8.importAPSelector(biFunction));
    }
}