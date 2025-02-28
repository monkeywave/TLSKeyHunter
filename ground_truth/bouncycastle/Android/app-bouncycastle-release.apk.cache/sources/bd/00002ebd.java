package org.bouncycastle.util.test;

/* loaded from: classes2.dex */
public interface TestResult {
    Throwable getException();

    boolean isSuccessful();

    String toString();
}