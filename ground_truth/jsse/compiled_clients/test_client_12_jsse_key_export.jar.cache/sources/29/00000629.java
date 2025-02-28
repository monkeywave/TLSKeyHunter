package org.bouncycastle.i18n.filter;

import javassist.bytecode.Opcode;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/i18n/filter/HTMLFilter.class */
public class HTMLFilter implements Filter {
    @Override // org.bouncycastle.i18n.filter.Filter
    public String doFilter(String str) {
        StringBuffer stringBuffer = new StringBuffer(str);
        int i = 0;
        while (i < stringBuffer.length()) {
            switch (stringBuffer.charAt(i)) {
                case Opcode.FLOAD_0 /* 34 */:
                    stringBuffer.replace(i, i + 1, "&#34");
                    break;
                case '#':
                    stringBuffer.replace(i, i + 1, "&#35");
                    break;
                case Opcode.FLOAD_2 /* 36 */:
                case Opcode.ALOAD_0 /* 42 */:
                case Opcode.ALOAD_2 /* 44 */:
                case '.':
                case '/':
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                case Opcode.ASTORE /* 58 */:
                case Opcode.ISTORE_2 /* 61 */:
                default:
                    i -= 3;
                    break;
                case Opcode.FLOAD_3 /* 37 */:
                    stringBuffer.replace(i, i + 1, "&#37");
                    break;
                case Opcode.DLOAD_0 /* 38 */:
                    stringBuffer.replace(i, i + 1, "&#38");
                    break;
                case Opcode.DLOAD_1 /* 39 */:
                    stringBuffer.replace(i, i + 1, "&#39");
                    break;
                case '(':
                    stringBuffer.replace(i, i + 1, "&#40");
                    break;
                case Opcode.DLOAD_3 /* 41 */:
                    stringBuffer.replace(i, i + 1, "&#41");
                    break;
                case Opcode.ALOAD_1 /* 43 */:
                    stringBuffer.replace(i, i + 1, "&#43");
                    break;
                case '-':
                    stringBuffer.replace(i, i + 1, "&#45");
                    break;
                case Opcode.ISTORE_0 /* 59 */:
                    stringBuffer.replace(i, i + 1, "&#59");
                    break;
                case '<':
                    stringBuffer.replace(i, i + 1, "&#60");
                    break;
                case Opcode.ISTORE_3 /* 62 */:
                    stringBuffer.replace(i, i + 1, "&#62");
                    break;
            }
            i += 4;
        }
        return stringBuffer.toString();
    }

    @Override // org.bouncycastle.i18n.filter.Filter
    public String doFilterUrl(String str) {
        return doFilter(str);
    }
}