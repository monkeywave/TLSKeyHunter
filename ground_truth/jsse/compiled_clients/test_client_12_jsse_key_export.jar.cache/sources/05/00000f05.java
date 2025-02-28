package org.bouncycastle.util.p012io.pem;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* renamed from: org.bouncycastle.util.io.pem.PemObject */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/io/pem/PemObject.class */
public class PemObject implements PemObjectGenerator {
    private static final List EMPTY_LIST = Collections.unmodifiableList(new ArrayList());
    private String type;
    private List headers;
    private byte[] content;

    public PemObject(String str, byte[] bArr) {
        this(str, EMPTY_LIST, bArr);
    }

    public PemObject(String str, List list, byte[] bArr) {
        this.type = str;
        this.headers = Collections.unmodifiableList(list);
        this.content = bArr;
    }

    public String getType() {
        return this.type;
    }

    public List getHeaders() {
        return this.headers;
    }

    public byte[] getContent() {
        return this.content;
    }

    @Override // org.bouncycastle.util.p012io.pem.PemObjectGenerator
    public PemObject generate() throws PemGenerationException {
        return this;
    }
}