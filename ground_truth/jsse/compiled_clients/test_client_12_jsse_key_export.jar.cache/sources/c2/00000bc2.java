package org.bouncycastle.jce.interfaces;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/interfaces/IESKey.class */
public interface IESKey extends Key {
    PublicKey getPublic();

    PrivateKey getPrivate();
}