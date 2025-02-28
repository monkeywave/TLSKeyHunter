package org.bouncycastle.util;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/StringList.class */
public interface StringList extends Iterable<String> {
    boolean add(String str);

    String get(int i);

    int size();

    String[] toStringArray();

    String[] toStringArray(int i, int i2);
}