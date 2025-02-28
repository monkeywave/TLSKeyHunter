package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.SSLSocket;

/* loaded from: classes2.dex */
class ProvSSLSocketDirect_8 extends ProvSSLSocketDirect {
    /* JADX INFO: Access modifiers changed from: protected */
    public ProvSSLSocketDirect_8(ContextData contextData) {
        super(contextData);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public ProvSSLSocketDirect_8(ContextData contextData, String str, int i) throws IOException, UnknownHostException {
        super(contextData, str, i);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public ProvSSLSocketDirect_8(ContextData contextData, String str, int i, InetAddress inetAddress, int i2) throws IOException, UnknownHostException {
        super(contextData, str, i, inetAddress, i2);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public ProvSSLSocketDirect_8(ContextData contextData, InetAddress inetAddress, int i) throws IOException {
        super(contextData, inetAddress, i);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public ProvSSLSocketDirect_8(ContextData contextData, InetAddress inetAddress, int i, InetAddress inetAddress2, int i2) throws IOException {
        super(contextData, inetAddress, i, inetAddress2, i2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProvSSLSocketDirect_8(ContextData contextData, boolean z, boolean z2, ProvSSLParameters provSSLParameters) {
        super(contextData, z, z2, provSSLParameters);
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