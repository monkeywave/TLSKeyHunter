package org.bouncycastle.asn1;

import java.io.IOException;

/* loaded from: classes.dex */
public interface ASN1SequenceParser extends ASN1Encodable, InMemoryRepresentable {
    ASN1Encodable readObject() throws IOException;
}