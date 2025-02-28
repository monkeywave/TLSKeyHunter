package org.bouncycastle.util;

import java.util.Collection;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/StreamParser.class */
public interface StreamParser {
    Object read() throws StreamParsingException;

    Collection readAll() throws StreamParsingException;
}