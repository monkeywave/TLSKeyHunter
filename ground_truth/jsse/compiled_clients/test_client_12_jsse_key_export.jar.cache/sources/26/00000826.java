package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/x509/SignatureCreator.class */
interface SignatureCreator {
    Signature createSignature(String str) throws NoSuchAlgorithmException, NoSuchProviderException;
}