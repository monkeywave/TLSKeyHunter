package org.bouncycastle.jsse.provider;

import java.security.Principal;
import java.util.List;
import org.bouncycastle.jsse.provider.NamedGroupInfo;
import org.bouncycastle.jsse.provider.SignatureSchemeInfo;

/* loaded from: classes2.dex */
class JsseSecurityParameters {
    NamedGroupInfo.PerConnection namedGroups;
    SignatureSchemeInfo.PerConnection signatureSchemes;
    List<byte[]> statusResponses;
    Principal[] trustedIssuers;

    /* JADX INFO: Access modifiers changed from: package-private */
    public void clear() {
        this.namedGroups = null;
        this.signatureSchemes = null;
        this.statusResponses = null;
        this.trustedIssuers = null;
    }
}