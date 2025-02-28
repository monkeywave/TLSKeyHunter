package org.bouncycastle.util.test;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/test/TestResult.class */
public interface TestResult {
    boolean isSuccessful();

    Throwable getException();

    String toString();
}