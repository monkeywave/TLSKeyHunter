package org.bouncycastle.asn1.eac;

import java.util.Enumeration;
import java.util.Hashtable;

/* loaded from: classes.dex */
public class Flags {
    int value;

    /* loaded from: classes.dex */
    private static class StringJoiner {
        boolean First = true;

        /* renamed from: b */
        StringBuffer f264b = new StringBuffer();
        String mSeparator;

        public StringJoiner(String str) {
            this.mSeparator = str;
        }

        public void add(String str) {
            if (this.First) {
                this.First = false;
            } else {
                this.f264b.append(this.mSeparator);
            }
            this.f264b.append(str);
        }

        public String toString() {
            return this.f264b.toString();
        }
    }

    public Flags() {
        this.value = 0;
    }

    public Flags(int i) {
        this.value = i;
    }

    String decode(Hashtable hashtable) {
        StringJoiner stringJoiner = new StringJoiner(" ");
        Enumeration keys = hashtable.keys();
        while (keys.hasMoreElements()) {
            Integer num = (Integer) keys.nextElement();
            if (isSet(num.intValue())) {
                stringJoiner.add((String) hashtable.get(num));
            }
        }
        return stringJoiner.toString();
    }

    public int getFlags() {
        return this.value;
    }

    public boolean isSet(int i) {
        return (i & this.value) != 0;
    }

    public void set(int i) {
        this.value = i | this.value;
    }
}