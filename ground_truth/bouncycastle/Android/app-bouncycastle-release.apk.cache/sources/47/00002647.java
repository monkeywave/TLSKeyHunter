package org.bouncycastle.jsse.java.security;

import java.security.AlgorithmParameters;
import java.security.Key;
import java.util.Set;

/* loaded from: classes2.dex */
public interface BCAlgorithmConstraints {
    boolean permits(Set<BCCryptoPrimitive> set, String str, AlgorithmParameters algorithmParameters);

    boolean permits(Set<BCCryptoPrimitive> set, String str, Key key, AlgorithmParameters algorithmParameters);

    boolean permits(Set<BCCryptoPrimitive> set, Key key);
}