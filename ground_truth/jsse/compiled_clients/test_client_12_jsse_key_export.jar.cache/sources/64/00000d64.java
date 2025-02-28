package org.bouncycastle.pqc.crypto.lms;

import java.io.IOException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Encodable;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/lms/LMSKeyParameters.class */
public abstract class LMSKeyParameters extends AsymmetricKeyParameter implements Encodable {
    /* JADX INFO: Access modifiers changed from: protected */
    public LMSKeyParameters(boolean z) {
        super(z);
    }

    public abstract byte[] getEncoded() throws IOException;
}