package org.bouncycastle.jce.interfaces;

import javax.crypto.interfaces.DHKey;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/interfaces/ElGamalKey.class */
public interface ElGamalKey extends DHKey {
    ElGamalParameterSpec getParameters();
}