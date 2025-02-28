package org.bouncycastle.asn1;

import java.io.IOException;

/* loaded from: classes.dex */
public interface InMemoryRepresentable {
    ASN1Primitive getLoadedObject() throws IOException;
}