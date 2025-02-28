package org.bouncycastle.pqc.crypto;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/StateAwareMessageSigner.class */
public interface StateAwareMessageSigner extends MessageSigner {
    AsymmetricKeyParameter getUpdatedPrivateKey();
}