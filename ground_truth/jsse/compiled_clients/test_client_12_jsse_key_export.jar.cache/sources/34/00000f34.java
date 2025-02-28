package org.bouncycastle.x509;

import java.io.InputStream;
import java.util.Collection;
import org.bouncycastle.x509.util.StreamParsingException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/x509/X509StreamParserSpi.class */
public abstract class X509StreamParserSpi {
    public abstract void engineInit(InputStream inputStream);

    public abstract Object engineRead() throws StreamParsingException;

    public abstract Collection engineReadAll() throws StreamParsingException;
}