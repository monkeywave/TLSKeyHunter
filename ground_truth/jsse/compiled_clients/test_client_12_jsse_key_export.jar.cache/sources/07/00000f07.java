package org.bouncycastle.util.p012io.pem;

import java.io.IOException;

/* renamed from: org.bouncycastle.util.io.pem.PemObjectParser */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/io/pem/PemObjectParser.class */
public interface PemObjectParser {
    Object parseObject(PemObject pemObject) throws IOException;
}