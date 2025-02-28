package javassist.bytecode;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javassist.CtClass;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/SignatureAttribute.class */
public class SignatureAttribute extends AttributeInfo {
    public static final String tag = "Signature";

    /* JADX INFO: Access modifiers changed from: package-private */
    public SignatureAttribute(ConstPool cp, int n, DataInputStream in) throws IOException {
        super(cp, n, in);
    }

    public SignatureAttribute(ConstPool cp, String signature) {
        super(cp, tag);
        int index = cp.addUtf8Info(signature);
        byte[] bvalue = {(byte) (index >>> 8), (byte) index};
        set(bvalue);
    }

    public String getSignature() {
        return getConstPool().getUtf8Info(ByteArray.readU16bit(get(), 0));
    }

    public void setSignature(String sig) {
        int index = getConstPool().addUtf8Info(sig);
        ByteArray.write16bit(index, this.info, 0);
    }

    @Override // javassist.bytecode.AttributeInfo
    public AttributeInfo copy(ConstPool newCp, Map<String, String> classnames) {
        return new SignatureAttribute(newCp, getSignature());
    }

    @Override // javassist.bytecode.AttributeInfo
    void renameClass(String oldname, String newname) {
        String sig = renameClass(getSignature(), oldname, newname);
        setSignature(sig);
    }

    @Override // javassist.bytecode.AttributeInfo
    void renameClass(Map<String, String> classnames) {
        String sig = renameClass(getSignature(), classnames);
        setSignature(sig);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String renameClass(String desc, String oldname, String newname) {
        Map<String, String> map = new HashMap<>();
        map.put(oldname, newname);
        return renameClass(desc, map);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String renameClass(String desc, Map<String, String> map) {
        char c;
        char c2;
        if (map == null) {
            return desc;
        }
        StringBuilder newdesc = new StringBuilder();
        int head = 0;
        int i = 0;
        while (true) {
            int j = desc.indexOf(76, i);
            if (j < 0) {
                break;
            }
            StringBuilder nameBuf = new StringBuilder();
            int k = j;
            while (true) {
                try {
                    k++;
                    c = desc.charAt(k);
                    if (c == ';') {
                        break;
                    }
                    nameBuf.append(c);
                    if (c == '<') {
                        while (true) {
                            k++;
                            c2 = desc.charAt(k);
                            if (c2 == '>') {
                                break;
                            }
                            nameBuf.append(c2);
                        }
                        nameBuf.append(c2);
                    }
                } catch (IndexOutOfBoundsException e) {
                }
            }
            i = k + 1;
            String name = nameBuf.toString();
            String name2 = map.get(name);
            if (name2 != null) {
                newdesc.append(desc.substring(head, j));
                newdesc.append('L');
                newdesc.append(name2);
                newdesc.append(c);
                head = i;
            }
        }
        if (head == 0) {
            return desc;
        }
        int len = desc.length();
        if (head < len) {
            newdesc.append(desc.substring(head, len));
        }
        return newdesc.toString();
    }

    private static boolean isNamePart(int c) {
        return (c == 59 || c == 60) ? false : true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/SignatureAttribute$Cursor.class */
    public static class Cursor {
        int position;

        private Cursor() {
            this.position = 0;
        }

        int indexOf(String s, int ch) throws BadBytecode {
            int i = s.indexOf(ch, this.position);
            if (i < 0) {
                throw SignatureAttribute.error(s);
            }
            this.position = i + 1;
            return i;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/SignatureAttribute$ClassSignature.class */
    public static class ClassSignature {
        TypeParameter[] params;
        ClassType superClass;
        ClassType[] interfaces;

        public ClassSignature(TypeParameter[] params, ClassType superClass, ClassType[] interfaces) {
            this.params = params == null ? new TypeParameter[0] : params;
            this.superClass = superClass == null ? ClassType.OBJECT : superClass;
            this.interfaces = interfaces == null ? new ClassType[0] : interfaces;
        }

        public ClassSignature(TypeParameter[] p) {
            this(p, null, null);
        }

        public TypeParameter[] getParameters() {
            return this.params;
        }

        public ClassType getSuperClass() {
            return this.superClass;
        }

        public ClassType[] getInterfaces() {
            return this.interfaces;
        }

        public String toString() {
            StringBuffer sbuf = new StringBuffer();
            TypeParameter.toString(sbuf, this.params);
            sbuf.append(" extends ").append(this.superClass);
            if (this.interfaces.length > 0) {
                sbuf.append(" implements ");
                Type.toString(sbuf, this.interfaces);
            }
            return sbuf.toString();
        }

        public String encode() {
            StringBuffer sbuf = new StringBuffer();
            if (this.params.length > 0) {
                sbuf.append('<');
                for (int i = 0; i < this.params.length; i++) {
                    this.params[i].encode(sbuf);
                }
                sbuf.append('>');
            }
            this.superClass.encode(sbuf);
            for (int i2 = 0; i2 < this.interfaces.length; i2++) {
                this.interfaces[i2].encode(sbuf);
            }
            return sbuf.toString();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/SignatureAttribute$MethodSignature.class */
    public static class MethodSignature {
        TypeParameter[] typeParams;
        Type[] params;
        Type retType;
        ObjectType[] exceptions;

        public MethodSignature(TypeParameter[] tp, Type[] params, Type ret, ObjectType[] ex) {
            this.typeParams = tp == null ? new TypeParameter[0] : tp;
            this.params = params == null ? new Type[0] : params;
            this.retType = ret == null ? new BaseType("void") : ret;
            this.exceptions = ex == null ? new ObjectType[0] : ex;
        }

        public TypeParameter[] getTypeParameters() {
            return this.typeParams;
        }

        public Type[] getParameterTypes() {
            return this.params;
        }

        public Type getReturnType() {
            return this.retType;
        }

        public ObjectType[] getExceptionTypes() {
            return this.exceptions;
        }

        public String toString() {
            StringBuffer sbuf = new StringBuffer();
            TypeParameter.toString(sbuf, this.typeParams);
            sbuf.append(" (");
            Type.toString(sbuf, this.params);
            sbuf.append(") ");
            sbuf.append(this.retType);
            if (this.exceptions.length > 0) {
                sbuf.append(" throws ");
                Type.toString(sbuf, this.exceptions);
            }
            return sbuf.toString();
        }

        public String encode() {
            StringBuffer sbuf = new StringBuffer();
            if (this.typeParams.length > 0) {
                sbuf.append('<');
                for (int i = 0; i < this.typeParams.length; i++) {
                    this.typeParams[i].encode(sbuf);
                }
                sbuf.append('>');
            }
            sbuf.append('(');
            for (int i2 = 0; i2 < this.params.length; i2++) {
                this.params[i2].encode(sbuf);
            }
            sbuf.append(')');
            this.retType.encode(sbuf);
            if (this.exceptions.length > 0) {
                for (int i3 = 0; i3 < this.exceptions.length; i3++) {
                    sbuf.append('^');
                    this.exceptions[i3].encode(sbuf);
                }
            }
            return sbuf.toString();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/SignatureAttribute$TypeParameter.class */
    public static class TypeParameter {
        String name;
        ObjectType superClass;
        ObjectType[] superInterfaces;

        TypeParameter(String sig, int nb, int ne, ObjectType sc, ObjectType[] si) {
            this.name = sig.substring(nb, ne);
            this.superClass = sc;
            this.superInterfaces = si;
        }

        public TypeParameter(String name, ObjectType superClass, ObjectType[] superInterfaces) {
            this.name = name;
            this.superClass = superClass;
            if (superInterfaces == null) {
                this.superInterfaces = new ObjectType[0];
            } else {
                this.superInterfaces = superInterfaces;
            }
        }

        public TypeParameter(String name) {
            this(name, null, null);
        }

        public String getName() {
            return this.name;
        }

        public ObjectType getClassBound() {
            return this.superClass;
        }

        public ObjectType[] getInterfaceBound() {
            return this.superInterfaces;
        }

        public String toString() {
            StringBuffer sbuf = new StringBuffer(getName());
            if (this.superClass != null) {
                sbuf.append(" extends ").append(this.superClass.toString());
            }
            int len = this.superInterfaces.length;
            if (len > 0) {
                for (int i = 0; i < len; i++) {
                    if (i > 0 || this.superClass != null) {
                        sbuf.append(" & ");
                    } else {
                        sbuf.append(" extends ");
                    }
                    sbuf.append(this.superInterfaces[i].toString());
                }
            }
            return sbuf.toString();
        }

        static void toString(StringBuffer sbuf, TypeParameter[] tp) {
            sbuf.append('<');
            for (int i = 0; i < tp.length; i++) {
                if (i > 0) {
                    sbuf.append(", ");
                }
                sbuf.append(tp[i]);
            }
            sbuf.append('>');
        }

        void encode(StringBuffer sb) {
            sb.append(this.name);
            if (this.superClass == null) {
                sb.append(":Ljava/lang/Object;");
            } else {
                sb.append(':');
                this.superClass.encode(sb);
            }
            for (int i = 0; i < this.superInterfaces.length; i++) {
                sb.append(':');
                this.superInterfaces[i].encode(sb);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/SignatureAttribute$TypeArgument.class */
    public static class TypeArgument {
        ObjectType arg;
        char wildcard;

        TypeArgument(ObjectType a, char w) {
            this.arg = a;
            this.wildcard = w;
        }

        public TypeArgument(ObjectType t) {
            this(t, ' ');
        }

        public TypeArgument() {
            this(null, '*');
        }

        public static TypeArgument subclassOf(ObjectType t) {
            return new TypeArgument(t, '+');
        }

        public static TypeArgument superOf(ObjectType t) {
            return new TypeArgument(t, '-');
        }

        public char getKind() {
            return this.wildcard;
        }

        public boolean isWildcard() {
            return this.wildcard != ' ';
        }

        public ObjectType getType() {
            return this.arg;
        }

        public String toString() {
            if (this.wildcard == '*') {
                return "?";
            }
            String type = this.arg.toString();
            if (this.wildcard == ' ') {
                return type;
            }
            if (this.wildcard == '+') {
                return "? extends " + type;
            }
            return "? super " + type;
        }

        static void encode(StringBuffer sb, TypeArgument[] args) {
            sb.append('<');
            for (TypeArgument ta : args) {
                if (ta.isWildcard()) {
                    sb.append(ta.wildcard);
                }
                if (ta.getType() != null) {
                    ta.getType().encode(sb);
                }
            }
            sb.append('>');
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/SignatureAttribute$Type.class */
    public static abstract class Type {
        abstract void encode(StringBuffer stringBuffer);

        static void toString(StringBuffer sbuf, Type[] ts) {
            for (int i = 0; i < ts.length; i++) {
                if (i > 0) {
                    sbuf.append(", ");
                }
                sbuf.append(ts[i]);
            }
        }

        public String jvmTypeName() {
            return toString();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/SignatureAttribute$BaseType.class */
    public static class BaseType extends Type {
        char descriptor;

        BaseType(char c) {
            this.descriptor = c;
        }

        public BaseType(String typeName) {
            this(Descriptor.m130of(typeName).charAt(0));
        }

        public char getDescriptor() {
            return this.descriptor;
        }

        public CtClass getCtlass() {
            return Descriptor.toPrimitiveClass(this.descriptor);
        }

        public String toString() {
            return Descriptor.toClassName(Character.toString(this.descriptor));
        }

        @Override // javassist.bytecode.SignatureAttribute.Type
        void encode(StringBuffer sb) {
            sb.append(this.descriptor);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/SignatureAttribute$ObjectType.class */
    public static abstract class ObjectType extends Type {
        public String encode() {
            StringBuffer sb = new StringBuffer();
            encode(sb);
            return sb.toString();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/SignatureAttribute$ClassType.class */
    public static class ClassType extends ObjectType {
        String name;
        TypeArgument[] arguments;
        public static ClassType OBJECT = new ClassType("java.lang.Object", null);

        static ClassType make(String s, int b, int e, TypeArgument[] targs, ClassType parent) {
            if (parent == null) {
                return new ClassType(s, b, e, targs);
            }
            return new NestedClassType(s, b, e, targs, parent);
        }

        ClassType(String signature, int begin, int end, TypeArgument[] targs) {
            this.name = signature.substring(begin, end).replace('/', '.');
            this.arguments = targs;
        }

        public ClassType(String className, TypeArgument[] args) {
            this.name = className;
            this.arguments = args;
        }

        public ClassType(String className) {
            this(className, null);
        }

        public String getName() {
            return this.name;
        }

        public TypeArgument[] getTypeArguments() {
            return this.arguments;
        }

        public ClassType getDeclaringClass() {
            return null;
        }

        public String toString() {
            StringBuffer sbuf = new StringBuffer();
            ClassType parent = getDeclaringClass();
            if (parent != null) {
                sbuf.append(parent.toString()).append('.');
            }
            return toString2(sbuf);
        }

        private String toString2(StringBuffer sbuf) {
            sbuf.append(this.name);
            if (this.arguments != null) {
                sbuf.append('<');
                int n = this.arguments.length;
                for (int i = 0; i < n; i++) {
                    if (i > 0) {
                        sbuf.append(", ");
                    }
                    sbuf.append(this.arguments[i].toString());
                }
                sbuf.append('>');
            }
            return sbuf.toString();
        }

        @Override // javassist.bytecode.SignatureAttribute.Type
        public String jvmTypeName() {
            StringBuffer sbuf = new StringBuffer();
            ClassType parent = getDeclaringClass();
            if (parent != null) {
                sbuf.append(parent.jvmTypeName()).append('$');
            }
            return toString2(sbuf);
        }

        @Override // javassist.bytecode.SignatureAttribute.Type
        void encode(StringBuffer sb) {
            sb.append('L');
            encode2(sb);
            sb.append(';');
        }

        void encode2(StringBuffer sb) {
            ClassType parent = getDeclaringClass();
            if (parent != null) {
                parent.encode2(sb);
                sb.append('$');
            }
            sb.append(this.name.replace('.', '/'));
            if (this.arguments != null) {
                TypeArgument.encode(sb, this.arguments);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/SignatureAttribute$NestedClassType.class */
    public static class NestedClassType extends ClassType {
        ClassType parent;

        NestedClassType(String s, int b, int e, TypeArgument[] targs, ClassType p) {
            super(s, b, e, targs);
            this.parent = p;
        }

        public NestedClassType(ClassType parent, String className, TypeArgument[] args) {
            super(className, args);
            this.parent = parent;
        }

        @Override // javassist.bytecode.SignatureAttribute.ClassType
        public ClassType getDeclaringClass() {
            return this.parent;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/SignatureAttribute$ArrayType.class */
    public static class ArrayType extends ObjectType {
        int dim;
        Type componentType;

        public ArrayType(int d, Type comp) {
            this.dim = d;
            this.componentType = comp;
        }

        public int getDimension() {
            return this.dim;
        }

        public Type getComponentType() {
            return this.componentType;
        }

        public String toString() {
            StringBuffer sbuf = new StringBuffer(this.componentType.toString());
            for (int i = 0; i < this.dim; i++) {
                sbuf.append("[]");
            }
            return sbuf.toString();
        }

        @Override // javassist.bytecode.SignatureAttribute.Type
        void encode(StringBuffer sb) {
            for (int i = 0; i < this.dim; i++) {
                sb.append('[');
            }
            this.componentType.encode(sb);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/SignatureAttribute$TypeVariable.class */
    public static class TypeVariable extends ObjectType {
        String name;

        TypeVariable(String sig, int begin, int end) {
            this.name = sig.substring(begin, end);
        }

        public TypeVariable(String name) {
            this.name = name;
        }

        public String getName() {
            return this.name;
        }

        public String toString() {
            return this.name;
        }

        @Override // javassist.bytecode.SignatureAttribute.Type
        void encode(StringBuffer sb) {
            sb.append('T').append(this.name).append(';');
        }
    }

    public static ClassSignature toClassSignature(String sig) throws BadBytecode {
        try {
            return parseSig(sig);
        } catch (IndexOutOfBoundsException e) {
            throw error(sig);
        }
    }

    public static MethodSignature toMethodSignature(String sig) throws BadBytecode {
        try {
            return parseMethodSig(sig);
        } catch (IndexOutOfBoundsException e) {
            throw error(sig);
        }
    }

    public static ObjectType toFieldSignature(String sig) throws BadBytecode {
        try {
            return parseObjectType(sig, new Cursor(), false);
        } catch (IndexOutOfBoundsException e) {
            throw error(sig);
        }
    }

    public static Type toTypeSignature(String sig) throws BadBytecode {
        try {
            return parseType(sig, new Cursor());
        } catch (IndexOutOfBoundsException e) {
            throw error(sig);
        }
    }

    private static ClassSignature parseSig(String sig) throws BadBytecode, IndexOutOfBoundsException {
        Cursor cur = new Cursor();
        TypeParameter[] tp = parseTypeParams(sig, cur);
        ClassType superClass = parseClassType(sig, cur);
        int sigLen = sig.length();
        List<ClassType> ifArray = new ArrayList<>();
        while (cur.position < sigLen && sig.charAt(cur.position) == 'L') {
            ifArray.add(parseClassType(sig, cur));
        }
        ClassType[] ifs = (ClassType[]) ifArray.toArray(new ClassType[ifArray.size()]);
        return new ClassSignature(tp, superClass, ifs);
    }

    private static MethodSignature parseMethodSig(String sig) throws BadBytecode {
        Cursor cur = new Cursor();
        TypeParameter[] tp = parseTypeParams(sig, cur);
        int i = cur.position;
        cur.position = i + 1;
        if (sig.charAt(i) != '(') {
            throw error(sig);
        }
        List<Type> params = new ArrayList<>();
        while (sig.charAt(cur.position) != ')') {
            params.add(parseType(sig, cur));
        }
        cur.position++;
        Type ret = parseType(sig, cur);
        int sigLen = sig.length();
        List<ObjectType> exceptions = new ArrayList<>();
        while (cur.position < sigLen && sig.charAt(cur.position) == '^') {
            cur.position++;
            ObjectType t = parseObjectType(sig, cur, false);
            if (t instanceof ArrayType) {
                throw error(sig);
            }
            exceptions.add(t);
        }
        Type[] p = (Type[]) params.toArray(new Type[params.size()]);
        ObjectType[] ex = (ObjectType[]) exceptions.toArray(new ObjectType[exceptions.size()]);
        return new MethodSignature(tp, p, ret, ex);
    }

    private static TypeParameter[] parseTypeParams(String sig, Cursor cur) throws BadBytecode {
        List<TypeParameter> typeParam = new ArrayList<>();
        if (sig.charAt(cur.position) == '<') {
            cur.position++;
            while (sig.charAt(cur.position) != '>') {
                int nameBegin = cur.position;
                int nameEnd = cur.indexOf(sig, 58);
                ObjectType classBound = parseObjectType(sig, cur, true);
                List<ObjectType> ifBound = new ArrayList<>();
                while (sig.charAt(cur.position) == ':') {
                    cur.position++;
                    ObjectType t = parseObjectType(sig, cur, false);
                    ifBound.add(t);
                }
                TypeParameter p = new TypeParameter(sig, nameBegin, nameEnd, classBound, (ObjectType[]) ifBound.toArray(new ObjectType[ifBound.size()]));
                typeParam.add(p);
            }
            cur.position++;
        }
        return (TypeParameter[]) typeParam.toArray(new TypeParameter[typeParam.size()]);
    }

    private static ObjectType parseObjectType(String sig, Cursor c, boolean dontThrow) throws BadBytecode {
        int begin = c.position;
        switch (sig.charAt(begin)) {
            case 'L':
                return parseClassType2(sig, c, null);
            case Opcode.BASTORE /* 84 */:
                int i = c.indexOf(sig, 59);
                return new TypeVariable(sig, begin + 1, i);
            case Opcode.DUP_X2 /* 91 */:
                return parseArray(sig, c);
            default:
                if (dontThrow) {
                    return null;
                }
                throw error(sig);
        }
    }

    private static ClassType parseClassType(String sig, Cursor c) throws BadBytecode {
        if (sig.charAt(c.position) == 'L') {
            return parseClassType2(sig, c, null);
        }
        throw error(sig);
    }

    private static ClassType parseClassType2(String sig, Cursor c, ClassType parent) throws BadBytecode {
        char t;
        TypeArgument[] targs;
        int start = c.position + 1;
        c.position = start;
        do {
            int i = c.position;
            c.position = i + 1;
            t = sig.charAt(i);
            if (t == '$' || t == '<') {
                break;
            }
        } while (t != ';');
        int end = c.position - 1;
        if (t == '<') {
            targs = parseTypeArgs(sig, c);
            int i2 = c.position;
            c.position = i2 + 1;
            t = sig.charAt(i2);
        } else {
            targs = null;
        }
        ClassType thisClass = ClassType.make(sig, start, end, targs, parent);
        if (t == '$' || t == '.') {
            c.position--;
            return parseClassType2(sig, c, thisClass);
        }
        return thisClass;
    }

    private static TypeArgument[] parseTypeArgs(String sig, Cursor c) throws BadBytecode {
        TypeArgument typeArgument;
        List<TypeArgument> args = new ArrayList<>();
        while (true) {
            int i = c.position;
            c.position = i + 1;
            char charAt = sig.charAt(i);
            char t = charAt;
            if (charAt != '>') {
                if (t == '*') {
                    typeArgument = new TypeArgument(null, '*');
                } else {
                    if (t != '+' && t != '-') {
                        t = ' ';
                        c.position--;
                    }
                    typeArgument = new TypeArgument(parseObjectType(sig, c, false), t);
                }
                TypeArgument ta = typeArgument;
                args.add(ta);
            } else {
                return (TypeArgument[]) args.toArray(new TypeArgument[args.size()]);
            }
        }
    }

    private static ObjectType parseArray(String sig, Cursor c) throws BadBytecode {
        int dim = 1;
        while (true) {
            int i = c.position + 1;
            c.position = i;
            if (sig.charAt(i) == '[') {
                dim++;
            } else {
                return new ArrayType(dim, parseType(sig, c));
            }
        }
    }

    private static Type parseType(String sig, Cursor c) throws BadBytecode {
        Type t = parseObjectType(sig, c, true);
        if (t == null) {
            int i = c.position;
            c.position = i + 1;
            t = new BaseType(sig.charAt(i));
        }
        return t;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static BadBytecode error(String sig) {
        return new BadBytecode("bad signature: " + sig);
    }
}