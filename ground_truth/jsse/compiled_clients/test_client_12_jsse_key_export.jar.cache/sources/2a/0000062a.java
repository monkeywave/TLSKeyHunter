package org.bouncycastle.i18n.filter;

import javassist.bytecode.Opcode;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/i18n/filter/SQLFilter.class */
public class SQLFilter implements Filter {
    @Override // org.bouncycastle.i18n.filter.Filter
    public String doFilter(String str) {
        StringBuffer stringBuffer = new StringBuffer(str);
        int i = 0;
        while (i < stringBuffer.length()) {
            switch (stringBuffer.charAt(i)) {
                case '\n':
                    stringBuffer.replace(i, i + 1, "\\n");
                    i++;
                    break;
                case '\r':
                    stringBuffer.replace(i, i + 1, "\\r");
                    i++;
                    break;
                case Opcode.FLOAD_0 /* 34 */:
                    stringBuffer.replace(i, i + 1, "\\\"");
                    i++;
                    break;
                case Opcode.DLOAD_1 /* 39 */:
                    stringBuffer.replace(i, i + 1, "\\'");
                    i++;
                    break;
                case '-':
                    stringBuffer.replace(i, i + 1, "\\-");
                    i++;
                    break;
                case '/':
                    stringBuffer.replace(i, i + 1, "\\/");
                    i++;
                    break;
                case Opcode.ISTORE_0 /* 59 */:
                    stringBuffer.replace(i, i + 1, "\\;");
                    i++;
                    break;
                case Opcode.ISTORE_2 /* 61 */:
                    stringBuffer.replace(i, i + 1, "\\=");
                    i++;
                    break;
                case Opcode.DUP2 /* 92 */:
                    stringBuffer.replace(i, i + 1, "\\\\");
                    i++;
                    break;
            }
            i++;
        }
        return stringBuffer.toString();
    }

    @Override // org.bouncycastle.i18n.filter.Filter
    public String doFilterUrl(String str) {
        return doFilter(str);
    }
}