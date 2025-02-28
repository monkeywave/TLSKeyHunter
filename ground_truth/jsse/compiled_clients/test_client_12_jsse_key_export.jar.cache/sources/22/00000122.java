package javassist.compiler;

import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtField;
import javassist.Modifier;
import javassist.NotFoundException;
import javassist.bytecode.ClassFile;
import javassist.bytecode.Descriptor;
import javassist.bytecode.MethodInfo;
import javassist.bytecode.Opcode;
import javassist.compiler.ast.ASTList;
import javassist.compiler.ast.ASTree;
import javassist.compiler.ast.Declarator;
import javassist.compiler.ast.Keyword;
import javassist.compiler.ast.Symbol;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/compiler/MemberResolver.class */
public class MemberResolver implements TokenId {
    private ClassPool classPool;
    private static final int YES = 0;

    /* renamed from: NO */
    private static final int f1NO = -1;
    private static final String INVALID = "<invalid>";
    private static Map<ClassPool, Reference<Map<String, String>>> invalidNamesMap = new WeakHashMap();
    private Map<String, String> invalidNames = null;

    public MemberResolver(ClassPool cp) {
        this.classPool = cp;
    }

    public ClassPool getClassPool() {
        return this.classPool;
    }

    private static void fatal() throws CompileError {
        throw new CompileError("fatal");
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/compiler/MemberResolver$Method.class */
    public static class Method {
        public CtClass declaring;
        public MethodInfo info;
        public int notmatch;

        public Method(CtClass c, MethodInfo i, int n) {
            this.declaring = c;
            this.info = i;
            this.notmatch = n;
        }

        public boolean isStatic() {
            int acc = this.info.getAccessFlags();
            return (acc & 8) != 0;
        }
    }

    public Method lookupMethod(CtClass clazz, CtClass currentClass, MethodInfo current, String methodName, int[] argTypes, int[] argDims, String[] argClassNames) throws CompileError {
        int res;
        Method maybe = null;
        if (current != null && clazz == currentClass && current.getName().equals(methodName) && (res = compareSignature(current.getDescriptor(), argTypes, argDims, argClassNames)) != f1NO) {
            Method r = new Method(clazz, current, res);
            if (res == 0) {
                return r;
            }
            maybe = r;
        }
        Method m = lookupMethod(clazz, methodName, argTypes, argDims, argClassNames, maybe != null);
        if (m != null) {
            return m;
        }
        return maybe;
    }

    private Method lookupMethod(CtClass clazz, String methodName, int[] argTypes, int[] argDims, String[] argClassNames, boolean onlyExact) throws CompileError {
        CtClass pclazz;
        int res;
        Method maybe = null;
        ClassFile cf = clazz.getClassFile2();
        if (cf != null) {
            List<MethodInfo> list = cf.getMethods();
            for (MethodInfo minfo : list) {
                if (minfo.getName().equals(methodName) && (minfo.getAccessFlags() & 64) == 0 && (res = compareSignature(minfo.getDescriptor(), argTypes, argDims, argClassNames)) != f1NO) {
                    Method r = new Method(clazz, minfo, res);
                    if (res == 0) {
                        return r;
                    }
                    if (maybe == null || maybe.notmatch > res) {
                        maybe = r;
                    }
                }
            }
        }
        if (onlyExact) {
            maybe = null;
        } else if (maybe != null) {
            return maybe;
        }
        int mod = clazz.getModifiers();
        boolean isIntf = Modifier.isInterface(mod);
        if (!isIntf) {
            try {
                CtClass pclazz2 = clazz.getSuperclass();
                if (pclazz2 != null) {
                    Method r2 = lookupMethod(pclazz2, methodName, argTypes, argDims, argClassNames, onlyExact);
                    if (r2 != null) {
                        return r2;
                    }
                }
            } catch (NotFoundException e) {
            }
        }
        try {
            CtClass[] ifs = clazz.getInterfaces();
            for (CtClass intf : ifs) {
                Method r3 = lookupMethod(intf, methodName, argTypes, argDims, argClassNames, onlyExact);
                if (r3 != null) {
                    return r3;
                }
            }
            if (isIntf && (pclazz = clazz.getSuperclass()) != null) {
                Method r4 = lookupMethod(pclazz, methodName, argTypes, argDims, argClassNames, onlyExact);
                if (r4 != null) {
                    return r4;
                }
            }
        } catch (NotFoundException e2) {
        }
        return maybe;
    }

    private int compareSignature(String desc, int[] argTypes, int[] argDims, String[] argClassNames) throws CompileError {
        int result = 0;
        int i = 1;
        int nArgs = argTypes.length;
        if (nArgs != Descriptor.numOfParameters(desc)) {
            return f1NO;
        }
        int len = desc.length();
        int n = 0;
        while (i < len) {
            int i2 = i;
            i++;
            char c = desc.charAt(i2);
            if (c == ')') {
                return n == nArgs ? result : f1NO;
            } else if (n >= nArgs) {
                return f1NO;
            } else {
                int dim = 0;
                while (c == '[') {
                    dim++;
                    int i3 = i;
                    i++;
                    c = desc.charAt(i3);
                }
                if (argTypes[n] == 412) {
                    if (dim == 0 && c != 'L') {
                        return f1NO;
                    }
                    if (c == 'L') {
                        i = desc.indexOf(59, i) + 1;
                    }
                } else if (argDims[n] != dim) {
                    if (dim != 0 || c != 'L' || !desc.startsWith("java/lang/Object;", i)) {
                        return f1NO;
                    }
                    i = desc.indexOf(59, i) + 1;
                    result++;
                    if (i <= 0) {
                        return f1NO;
                    }
                } else if (c == 'L') {
                    int j = desc.indexOf(59, i);
                    if (j < 0 || argTypes[n] != 307) {
                        return f1NO;
                    }
                    String cname = desc.substring(i, j);
                    if (!cname.equals(argClassNames[n])) {
                        CtClass clazz = lookupClassByJvmName(argClassNames[n]);
                        try {
                            if (clazz.subtypeOf(lookupClassByJvmName(cname))) {
                                result++;
                            } else {
                                return f1NO;
                            }
                        } catch (NotFoundException e) {
                            result++;
                        }
                    }
                    i = j + 1;
                } else {
                    int t = descToType(c);
                    int at = argTypes[n];
                    if (t == at) {
                        continue;
                    } else if (t != 324) {
                        return f1NO;
                    } else {
                        if (at == 334 || at == 303 || at == 306) {
                            result++;
                        } else {
                            return f1NO;
                        }
                    }
                }
                n++;
            }
        }
        return f1NO;
    }

    public CtField lookupFieldByJvmName2(String jvmClassName, Symbol fieldSym, ASTree expr) throws NoFieldException {
        String field = fieldSym.get();
        try {
            CtClass cc = lookupClass(jvmToJavaName(jvmClassName), true);
            try {
                return cc.getField(field);
            } catch (NotFoundException e) {
                throw new NoFieldException(javaToJvmName(cc.getName()) + "$" + field, expr);
            }
        } catch (CompileError e2) {
            throw new NoFieldException(jvmClassName + "/" + field, expr);
        }
    }

    public CtField lookupFieldByJvmName(String jvmClassName, Symbol fieldName) throws CompileError {
        return lookupField(jvmToJavaName(jvmClassName), fieldName);
    }

    public CtField lookupField(String className, Symbol fieldName) throws CompileError {
        CtClass cc = lookupClass(className, false);
        try {
            return cc.getField(fieldName.get());
        } catch (NotFoundException e) {
            throw new CompileError("no such field: " + fieldName.get());
        }
    }

    public CtClass lookupClassByName(ASTList name) throws CompileError {
        return lookupClass(Declarator.astToClassName(name, '.'), false);
    }

    public CtClass lookupClassByJvmName(String jvmName) throws CompileError {
        return lookupClass(jvmToJavaName(jvmName), false);
    }

    public CtClass lookupClass(Declarator decl) throws CompileError {
        return lookupClass(decl.getType(), decl.getArrayDim(), decl.getClassName());
    }

    public CtClass lookupClass(int type, int dim, String classname) throws CompileError {
        String typeName;
        if (type == 307) {
            CtClass clazz = lookupClassByJvmName(classname);
            if (dim > 0) {
                typeName = clazz.getName();
            } else {
                return clazz;
            }
        } else {
            typeName = getTypeName(type);
        }
        while (true) {
            String cname = typeName;
            int i = dim;
            dim += f1NO;
            if (i > 0) {
                typeName = cname + "[]";
            } else {
                return lookupClass(cname, false);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String getTypeName(int type) throws CompileError {
        String cname = "";
        switch (type) {
            case TokenId.BOOLEAN /* 301 */:
                cname = "boolean";
                break;
            case TokenId.BYTE /* 303 */:
                cname = "byte";
                break;
            case TokenId.CHAR /* 306 */:
                cname = "char";
                break;
            case TokenId.DOUBLE /* 312 */:
                cname = "double";
                break;
            case TokenId.FLOAT /* 317 */:
                cname = "float";
                break;
            case TokenId.INT /* 324 */:
                cname = "int";
                break;
            case TokenId.LONG /* 326 */:
                cname = "long";
                break;
            case TokenId.SHORT /* 334 */:
                cname = "short";
                break;
            case TokenId.VOID /* 344 */:
                cname = "void";
                break;
            default:
                fatal();
                break;
        }
        return cname;
    }

    public CtClass lookupClass(String name, boolean notCheckInner) throws CompileError {
        CtClass cc;
        Map<String, String> cache = getInvalidNames();
        String found = cache.get(name);
        if (found == INVALID) {
            throw new CompileError("no such class: " + name);
        }
        if (found != null) {
            try {
                return this.classPool.get(found);
            } catch (NotFoundException e) {
            }
        }
        try {
            cc = lookupClass0(name, notCheckInner);
        } catch (NotFoundException e2) {
            cc = searchImports(name);
        }
        cache.put(name, cc.getName());
        return cc;
    }

    public static int getInvalidMapSize() {
        return invalidNamesMap.size();
    }

    private Map<String, String> getInvalidNames() {
        Map<String, String> ht = this.invalidNames;
        if (ht == null) {
            synchronized (MemberResolver.class) {
                Reference<Map<String, String>> ref = invalidNamesMap.get(this.classPool);
                if (ref != null) {
                    ht = ref.get();
                }
                if (ht == null) {
                    ht = new Hashtable<>();
                    invalidNamesMap.put(this.classPool, new WeakReference(ht));
                }
            }
            this.invalidNames = ht;
        }
        return ht;
    }

    private CtClass searchImports(String orgName) throws CompileError {
        if (orgName.indexOf(46) < 0) {
            Iterator<String> it = this.classPool.getImportedPackages();
            while (it.hasNext()) {
                String pac = it.next();
                String fqName = pac.replaceAll("\\.$", "") + "." + orgName;
                try {
                    return this.classPool.get(fqName);
                } catch (NotFoundException e) {
                    if (pac.endsWith("." + orgName)) {
                        return this.classPool.get(pac);
                    }
                    continue;
                }
            }
        }
        getInvalidNames().put(orgName, INVALID);
        throw new CompileError("no such class: " + orgName);
    }

    private CtClass lookupClass0(String classname, boolean notCheckInner) throws NotFoundException {
        CtClass cc = null;
        do {
            try {
                cc = this.classPool.get(classname);
            } catch (NotFoundException e) {
                int i = classname.lastIndexOf(46);
                if (notCheckInner || i < 0) {
                    throw e;
                }
                StringBuffer sbuf = new StringBuffer(classname);
                sbuf.setCharAt(i, '$');
                classname = sbuf.toString();
            }
        } while (cc == null);
        return cc;
    }

    public String resolveClassName(ASTList name) throws CompileError {
        if (name == null) {
            return null;
        }
        return javaToJvmName(lookupClassByName(name).getName());
    }

    public String resolveJvmClassName(String jvmName) throws CompileError {
        if (jvmName == null) {
            return null;
        }
        return javaToJvmName(lookupClassByJvmName(jvmName).getName());
    }

    public static CtClass getSuperclass(CtClass c) throws CompileError {
        try {
            CtClass sc = c.getSuperclass();
            if (sc != null) {
                return sc;
            }
        } catch (NotFoundException e) {
        }
        throw new CompileError("cannot find the super class of " + c.getName());
    }

    public static CtClass getSuperInterface(CtClass c, String interfaceName) throws CompileError {
        try {
            CtClass[] intfs = c.getInterfaces();
            for (int i = 0; i < intfs.length; i++) {
                if (intfs[i].getName().equals(interfaceName)) {
                    return intfs[i];
                }
            }
        } catch (NotFoundException e) {
        }
        throw new CompileError("cannot find the super interface " + interfaceName + " of " + c.getName());
    }

    public static String javaToJvmName(String classname) {
        return classname.replace('.', '/');
    }

    public static String jvmToJavaName(String classname) {
        return classname.replace('/', '.');
    }

    public static int descToType(char c) throws CompileError {
        switch (c) {
            case 'B':
                return TokenId.BYTE;
            case 'C':
                return TokenId.CHAR;
            case 'D':
                return TokenId.DOUBLE;
            case 'E':
            case Opcode.DSTORE_0 /* 71 */:
            case Opcode.DSTORE_1 /* 72 */:
            case Opcode.ASTORE_0 /* 75 */:
            case Opcode.ASTORE_2 /* 77 */:
            case Opcode.ASTORE_3 /* 78 */:
            case Opcode.IASTORE /* 79 */:
            case Opcode.LASTORE /* 80 */:
            case Opcode.FASTORE /* 81 */:
            case 'R':
            case Opcode.BASTORE /* 84 */:
            case 'U':
            case Opcode.POP /* 87 */:
            case Opcode.POP2 /* 88 */:
            case Opcode.DUP /* 89 */:
            default:
                fatal();
                return TokenId.VOID;
            case 'F':
                return TokenId.FLOAT;
            case 'I':
                return TokenId.INT;
            case Opcode.DSTORE_3 /* 74 */:
                return TokenId.LONG;
            case 'L':
            case Opcode.DUP_X2 /* 91 */:
                return TokenId.CLASS;
            case Opcode.AASTORE /* 83 */:
                return TokenId.SHORT;
            case Opcode.SASTORE /* 86 */:
                return TokenId.VOID;
            case 'Z':
                return TokenId.BOOLEAN;
        }
    }

    public static int getModifiers(ASTList mods) {
        int m = 0;
        while (mods != null) {
            Keyword k = (Keyword) mods.head();
            mods = mods.tail();
            switch (k.get()) {
                case TokenId.ABSTRACT /* 300 */:
                    m |= 1024;
                    break;
                case TokenId.FINAL /* 315 */:
                    m |= 16;
                    break;
                case TokenId.PRIVATE /* 330 */:
                    m |= 2;
                    break;
                case TokenId.PROTECTED /* 331 */:
                    m |= 4;
                    break;
                case TokenId.PUBLIC /* 332 */:
                    m |= 1;
                    break;
                case TokenId.STATIC /* 335 */:
                    m |= 8;
                    break;
                case TokenId.SYNCHRONIZED /* 338 */:
                    m |= 32;
                    break;
                case TokenId.TRANSIENT /* 342 */:
                    m |= 128;
                    break;
                case TokenId.VOLATILE /* 345 */:
                    m |= 64;
                    break;
                case TokenId.STRICT /* 347 */:
                    m |= 2048;
                    break;
            }
        }
        return m;
    }
}