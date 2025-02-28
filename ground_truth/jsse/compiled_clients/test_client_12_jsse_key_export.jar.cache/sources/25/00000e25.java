package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.PublicKey;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/interfaces/NHPublicKey.class */
public interface NHPublicKey extends NHKey, PublicKey {
    byte[] getPublicData();
}