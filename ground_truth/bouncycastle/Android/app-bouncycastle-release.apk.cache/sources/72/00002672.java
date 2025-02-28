package org.bouncycastle.jsse.provider;

import java.util.List;
import javax.net.ssl.ExtendedSSLSession;
import org.bouncycastle.jsse.BCSNIServerName;

/* loaded from: classes2.dex */
class ImportSSLSession_8 extends ImportSSLSession_7 {
    ImportSSLSession_8(ExtendedSSLSession extendedSSLSession) {
        super(extendedSSLSession);
    }

    @Override // org.bouncycastle.jsse.provider.ImportSSLSession_7, org.bouncycastle.jsse.BCExtendedSSLSession
    public List<BCSNIServerName> getRequestedServerNames() {
        return JsseUtils_8.importSNIServerNames(this.sslSession.getRequestedServerNames());
    }
}