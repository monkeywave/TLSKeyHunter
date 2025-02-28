package org.bouncycastle.jce.interfaces;

import org.bouncycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/interfaces/GOST3410Params.class */
public interface GOST3410Params {
    String getPublicKeyParamSetOID();

    String getDigestParamSetOID();

    String getEncryptionParamSetOID();

    GOST3410PublicKeyParameterSetSpec getPublicKeyParameters();
}