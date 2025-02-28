package org.bouncycastle.jsse.provider;

import java.util.List;
import javax.net.ssl.SNIServerName;
import org.bouncycastle.jsse.BCExtendedSSLSession;

/* loaded from: classes2.dex */
class ExportSSLSession_8 extends ExportSSLSession_7 {
    ExportSSLSession_8(BCExtendedSSLSession bCExtendedSSLSession) {
        super(bCExtendedSSLSession);
    }

    @Override // javax.net.ssl.ExtendedSSLSession
    public List<SNIServerName> getRequestedServerNames() {
        return JsseUtils_8.exportSNIServerNames(this.sslSession.getRequestedServerNames());
    }
}