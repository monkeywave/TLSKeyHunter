package javassist.util.proxy;

import java.lang.invoke.MethodHandles;
import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import javassist.CannotCompileException;
import javassist.bytecode.Bytecode;
import javassist.bytecode.ClassFile;
import javassist.bytecode.CodeAttribute;
import javassist.bytecode.ConstPool;
import javassist.bytecode.Descriptor;
import javassist.bytecode.DuplicateMemberException;
import javassist.bytecode.ExceptionsAttribute;
import javassist.bytecode.FieldInfo;
import javassist.bytecode.MethodInfo;
import javassist.bytecode.Opcode;
import javassist.bytecode.SignatureAttribute;
import javassist.bytecode.StackMapTable;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/util/proxy/ProxyFactory.class */
public class ProxyFactory {
    private String classname;
    private String basename;
    private String superName;
    private static final String HOLDER = "_methods_";
    private static final String HOLDER_TYPE = "[Ljava/lang/reflect/Method;";
    private static final String FILTER_SIGNATURE_FIELD = "_filter_signature";
    private static final String FILTER_SIGNATURE_TYPE = "[B";
    private static final String HANDLER = "handler";
    private static final String NULL_INTERCEPTOR_HOLDER = "javassist.util.proxy.RuntimeSupport";
    private static final String DEFAULT_INTERCEPTOR = "default_interceptor";
    private static final String HANDLER_SETTER = "setHandler";
    private static final String HANDLER_GETTER = "getHandler";
    private static final String SERIAL_VERSION_UID_FIELD = "serialVersionUID";
    private static final String SERIAL_VERSION_UID_TYPE = "J";
    private static final long SERIAL_VERSION_UID_VALUE = -1;
    private static final String packageForJavaBase = "javassist.util.proxy.";
    private static final String HANDLER_GETTER_KEY = "getHandler:()";
    public static boolean onlyPublicMethods = false;
    private static final Class<?> OBJECT_TYPE = Object.class;
    private static final String HANDLER_TYPE = 'L' + MethodHandler.class.getName().replace('.', '/') + ';';
    private static final String HANDLER_SETTER_TYPE = "(" + HANDLER_TYPE + ")V";
    private static final String HANDLER_GETTER_TYPE = "()" + HANDLER_TYPE;
    public static volatile boolean useCache = true;
    public static volatile boolean useWriteReplace = true;
    private static Map<ClassLoader, Map<String, ProxyDetails>> proxyCache = new WeakHashMap();
    private static char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    public static ClassLoaderProvider classLoaderProvider = new ClassLoaderProvider() { // from class: javassist.util.proxy.ProxyFactory.1
        @Override // javassist.util.proxy.ProxyFactory.ClassLoaderProvider
        public ClassLoader get(ProxyFactory pf) {
            return pf.getClassLoader0();
        }
    };
    public static UniqueName nameGenerator = new UniqueName() { // from class: javassist.util.proxy.ProxyFactory.2
        private final String sep = "_$$_jvst" + Integer.toHexString(hashCode() & 4095) + "_";
        private int counter = 0;

        @Override // javassist.util.proxy.ProxyFactory.UniqueName
        public String get(String classname) {
            StringBuilder append = new StringBuilder().append(classname).append(this.sep);
            int i = this.counter;
            this.counter = i + 1;
            return append.append(Integer.toHexString(i)).toString();
        }
    };
    private static Comparator<Map.Entry<String, Method>> sorter = new Comparator<Map.Entry<String, Method>>() { // from class: javassist.util.proxy.ProxyFactory.3
        @Override // java.util.Comparator
        public int compare(Map.Entry<String, Method> e1, Map.Entry<String, Method> e2) {
            return e1.getKey().compareTo(e2.getKey());
        }
    };
    private Class<?> superClass = null;
    private Class<?>[] interfaces = null;
    private MethodFilter methodFilter = null;
    private MethodHandler handler = null;
    private byte[] signature = null;
    private List<Map.Entry<String, Method>> signatureMethods = null;
    private boolean hasGetHandler = false;
    private Class<?> thisClass = null;
    private String genericSignature = null;
    public String writeDirectory = null;
    private boolean factoryUseCache = useCache;
    private boolean factoryWriteReplace = useWriteReplace;

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/util/proxy/ProxyFactory$ClassLoaderProvider.class */
    public interface ClassLoaderProvider {
        ClassLoader get(ProxyFactory proxyFactory);
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/util/proxy/ProxyFactory$UniqueName.class */
    public interface UniqueName {
        String get(String str);
    }

    public boolean isUseCache() {
        return this.factoryUseCache;
    }

    public void setUseCache(boolean useCache2) {
        if (this.handler != null && useCache2) {
            throw new RuntimeException("caching cannot be enabled if the factory default interceptor has been set");
        }
        this.factoryUseCache = useCache2;
    }

    public boolean isUseWriteReplace() {
        return this.factoryWriteReplace;
    }

    public void setUseWriteReplace(boolean useWriteReplace2) {
        this.factoryWriteReplace = useWriteReplace2;
    }

    public static boolean isProxyClass(Class<?> cl) {
        return Proxy.class.isAssignableFrom(cl);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:javassist/util/proxy/ProxyFactory$ProxyDetails.class */
    public static class ProxyDetails {
        byte[] signature;
        Reference<Class<?>> proxyClass;
        boolean isUseWriteReplace;

        ProxyDetails(byte[] signature, Class<?> proxyClass, boolean isUseWriteReplace) {
            this.signature = signature;
            this.proxyClass = new WeakReference(proxyClass);
            this.isUseWriteReplace = isUseWriteReplace;
        }
    }

    public void setSuperclass(Class<?> clazz) {
        this.superClass = clazz;
        this.signature = null;
    }

    public Class<?> getSuperclass() {
        return this.superClass;
    }

    public void setInterfaces(Class<?>[] ifs) {
        this.interfaces = ifs;
        this.signature = null;
    }

    public Class<?>[] getInterfaces() {
        return this.interfaces;
    }

    public void setFilter(MethodFilter mf) {
        this.methodFilter = mf;
        this.signature = null;
    }

    public void setGenericSignature(String sig) {
        this.genericSignature = sig;
    }

    public Class<?> createClass() {
        if (this.signature == null) {
            computeSignature(this.methodFilter);
        }
        return createClass1(null);
    }

    public Class<?> createClass(MethodFilter filter) {
        computeSignature(filter);
        return createClass1(null);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Class<?> createClass(byte[] signature) {
        installSignature(signature);
        return createClass1(null);
    }

    public Class<?> createClass(MethodHandles.Lookup lookup) {
        if (this.signature == null) {
            computeSignature(this.methodFilter);
        }
        return createClass1(lookup);
    }

    public Class<?> createClass(MethodHandles.Lookup lookup, MethodFilter filter) {
        computeSignature(filter);
        return createClass1(lookup);
    }

    Class<?> createClass(MethodHandles.Lookup lookup, byte[] signature) {
        installSignature(signature);
        return createClass1(lookup);
    }

    private Class<?> createClass1(MethodHandles.Lookup lookup) {
        Class<?> result = this.thisClass;
        if (result == null) {
            ClassLoader cl = getClassLoader();
            synchronized (proxyCache) {
                if (this.factoryUseCache) {
                    createClass2(cl, lookup);
                } else {
                    createClass3(cl, lookup);
                }
                result = this.thisClass;
                this.thisClass = null;
            }
        }
        return result;
    }

    public String getKey(Class<?> superClass, Class<?>[] interfaces, byte[] signature, boolean useWriteReplace2) {
        StringBuffer sbuf = new StringBuffer();
        if (superClass != null) {
            sbuf.append(superClass.getName());
        }
        sbuf.append(":");
        for (Class<?> cls : interfaces) {
            sbuf.append(cls.getName());
            sbuf.append(":");
        }
        for (byte b : signature) {
            int lo = b & 15;
            int hi = (b >> 4) & 15;
            sbuf.append(hexDigits[lo]);
            sbuf.append(hexDigits[hi]);
        }
        if (useWriteReplace2) {
            sbuf.append(":w");
        }
        return sbuf.toString();
    }

    private void createClass2(ClassLoader cl, MethodHandles.Lookup lookup) {
        String key = getKey(this.superClass, this.interfaces, this.signature, this.factoryWriteReplace);
        Map<String, ProxyDetails> cacheForTheLoader = proxyCache.get(cl);
        if (cacheForTheLoader == null) {
            cacheForTheLoader = new HashMap<>();
            proxyCache.put(cl, cacheForTheLoader);
        }
        ProxyDetails details = cacheForTheLoader.get(key);
        if (details != null) {
            Reference<Class<?>> reference = details.proxyClass;
            this.thisClass = reference.get();
            if (this.thisClass != null) {
                return;
            }
        }
        createClass3(cl, lookup);
        cacheForTheLoader.put(key, new ProxyDetails(this.signature, this.thisClass, this.factoryWriteReplace));
    }

    private void createClass3(ClassLoader cl, MethodHandles.Lookup lookup) {
        allocateClassName();
        try {
            ClassFile cf = make();
            if (this.writeDirectory != null) {
                FactoryHelper.writeFile(cf, this.writeDirectory);
            }
            if (lookup == null) {
                this.thisClass = FactoryHelper.toClass(cf, getClassInTheSamePackage(), cl, getDomain());
            } else {
                this.thisClass = FactoryHelper.toClass(cf, lookup);
            }
            setField(FILTER_SIGNATURE_FIELD, this.signature);
            if (!this.factoryUseCache) {
                setField(DEFAULT_INTERCEPTOR, this.handler);
            }
        } catch (CannotCompileException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    private Class<?> getClassInTheSamePackage() {
        if (this.basename.startsWith(packageForJavaBase)) {
            return getClass();
        }
        if (this.superClass != null && this.superClass != OBJECT_TYPE) {
            return this.superClass;
        }
        if (this.interfaces != null && this.interfaces.length > 0) {
            return this.interfaces[0];
        }
        return getClass();
    }

    private void setField(String fieldName, Object value) {
        if (this.thisClass != null && value != null) {
            try {
                Field f = this.thisClass.getField(fieldName);
                SecurityActions.setAccessible(f, true);
                f.set(null, value);
                SecurityActions.setAccessible(f, false);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] getFilterSignature(Class<?> clazz) {
        return (byte[]) getField(clazz, FILTER_SIGNATURE_FIELD);
    }

    private static Object getField(Class<?> clazz, String fieldName) {
        try {
            Field f = clazz.getField(fieldName);
            f.setAccessible(true);
            Object value = f.get(null);
            f.setAccessible(false);
            return value;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static MethodHandler getHandler(Proxy p) {
        try {
            Field f = p.getClass().getDeclaredField(HANDLER);
            f.setAccessible(true);
            Object value = f.get(p);
            f.setAccessible(false);
            return (MethodHandler) value;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected ClassLoader getClassLoader() {
        return classLoaderProvider.get(this);
    }

    protected ClassLoader getClassLoader0() {
        ClassLoader loader = null;
        if (this.superClass != null && !this.superClass.getName().equals("java.lang.Object")) {
            loader = this.superClass.getClassLoader();
        } else if (this.interfaces != null && this.interfaces.length > 0) {
            loader = this.interfaces[0].getClassLoader();
        }
        if (loader == null) {
            loader = getClass().getClassLoader();
            if (loader == null) {
                loader = Thread.currentThread().getContextClassLoader();
                if (loader == null) {
                    loader = ClassLoader.getSystemClassLoader();
                }
            }
        }
        return loader;
    }

    protected ProtectionDomain getDomain() {
        Class<?> clazz;
        if (this.superClass != null && !this.superClass.getName().equals("java.lang.Object")) {
            clazz = this.superClass;
        } else if (this.interfaces != null && this.interfaces.length > 0) {
            clazz = this.interfaces[0];
        } else {
            clazz = getClass();
        }
        return clazz.getProtectionDomain();
    }

    public Object create(Class<?>[] paramTypes, Object[] args, MethodHandler mh) throws NoSuchMethodException, IllegalArgumentException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Object obj = create(paramTypes, args);
        ((Proxy) obj).setHandler(mh);
        return obj;
    }

    public Object create(Class<?>[] paramTypes, Object[] args) throws NoSuchMethodException, IllegalArgumentException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Class<?> c = createClass();
        Constructor<?> cons = c.getConstructor(paramTypes);
        return cons.newInstance(args);
    }

    @Deprecated
    public void setHandler(MethodHandler mi) {
        if (this.factoryUseCache && mi != null) {
            this.factoryUseCache = false;
            this.thisClass = null;
        }
        this.handler = mi;
        setField(DEFAULT_INTERCEPTOR, this.handler);
    }

    private static String makeProxyName(String classname) {
        String str;
        synchronized (nameGenerator) {
            str = nameGenerator.get(classname);
        }
        return str;
    }

    private ClassFile make() throws CannotCompileException {
        ClassFile cf = new ClassFile(false, this.classname, this.superName);
        cf.setAccessFlags(1);
        setInterfaces(cf, this.interfaces, this.hasGetHandler ? Proxy.class : ProxyObject.class);
        ConstPool pool = cf.getConstPool();
        if (!this.factoryUseCache) {
            FieldInfo finfo = new FieldInfo(pool, DEFAULT_INTERCEPTOR, HANDLER_TYPE);
            finfo.setAccessFlags(9);
            cf.addField(finfo);
        }
        FieldInfo finfo2 = new FieldInfo(pool, HANDLER, HANDLER_TYPE);
        finfo2.setAccessFlags(2);
        cf.addField(finfo2);
        FieldInfo finfo3 = new FieldInfo(pool, FILTER_SIGNATURE_FIELD, FILTER_SIGNATURE_TYPE);
        finfo3.setAccessFlags(9);
        cf.addField(finfo3);
        FieldInfo finfo4 = new FieldInfo(pool, SERIAL_VERSION_UID_FIELD, SERIAL_VERSION_UID_TYPE);
        finfo4.setAccessFlags(25);
        cf.addField(finfo4);
        if (this.genericSignature != null) {
            SignatureAttribute sa = new SignatureAttribute(pool, this.genericSignature);
            cf.addAttribute(sa);
        }
        makeConstructors(this.classname, cf, pool, this.classname);
        List<Find2MethodsArgs> forwarders = new ArrayList<>();
        int s = overrideMethods(cf, pool, this.classname, forwarders);
        addClassInitializer(cf, pool, this.classname, s, forwarders);
        addSetter(this.classname, cf, pool);
        if (!this.hasGetHandler) {
            addGetter(this.classname, cf, pool);
        }
        if (this.factoryWriteReplace) {
            try {
                cf.addMethod(makeWriteReplace(pool));
            } catch (DuplicateMemberException e) {
            }
        }
        this.thisClass = null;
        return cf;
    }

    private void checkClassAndSuperName() {
        if (this.interfaces == null) {
            this.interfaces = new Class[0];
        }
        if (this.superClass == null) {
            this.superClass = OBJECT_TYPE;
            this.superName = this.superClass.getName();
            this.basename = this.interfaces.length == 0 ? this.superName : this.interfaces[0].getName();
        } else {
            this.superName = this.superClass.getName();
            this.basename = this.superName;
        }
        if (Modifier.isFinal(this.superClass.getModifiers())) {
            throw new RuntimeException(this.superName + " is final");
        }
        if (this.basename.startsWith("java.") || this.basename.startsWith("jdk.") || onlyPublicMethods) {
            this.basename = packageForJavaBase + this.basename.replace('.', '_');
        }
    }

    private void allocateClassName() {
        this.classname = makeProxyName(this.basename);
    }

    private void makeSortedMethodList() {
        checkClassAndSuperName();
        this.hasGetHandler = false;
        Map<String, Method> allMethods = getMethods(this.superClass, this.interfaces);
        this.signatureMethods = new ArrayList(allMethods.entrySet());
        Collections.sort(this.signatureMethods, sorter);
    }

    private void computeSignature(MethodFilter filter) {
        makeSortedMethodList();
        int l = this.signatureMethods.size();
        int maxBytes = (l + 7) >> 3;
        this.signature = new byte[maxBytes];
        for (int idx = 0; idx < l; idx++) {
            Method m = this.signatureMethods.get(idx).getValue();
            int mod = m.getModifiers();
            if (!Modifier.isFinal(mod) && !Modifier.isStatic(mod) && isVisible(mod, this.basename, m) && (filter == null || filter.isHandled(m))) {
                setBit(this.signature, idx);
            }
        }
    }

    private void installSignature(byte[] signature) {
        makeSortedMethodList();
        int l = this.signatureMethods.size();
        int maxBytes = (l + 7) >> 3;
        if (signature.length != maxBytes) {
            throw new RuntimeException("invalid filter signature length for deserialized proxy class");
        }
        this.signature = signature;
    }

    private boolean testBit(byte[] signature, int idx) {
        int byteIdx = idx >> 3;
        if (byteIdx > signature.length) {
            return false;
        }
        int bitIdx = idx & 7;
        int mask = 1 << bitIdx;
        return (signature[byteIdx] & mask) != 0;
    }

    private void setBit(byte[] signature, int idx) {
        int byteIdx = idx >> 3;
        if (byteIdx < signature.length) {
            int bitIdx = idx & 7;
            int mask = 1 << bitIdx;
            signature[byteIdx] = (byte) (signature[byteIdx] | mask);
        }
    }

    private static void setInterfaces(ClassFile cf, Class<?>[] interfaces, Class<?> proxyClass) {
        String[] list;
        String setterIntf = proxyClass.getName();
        if (interfaces == null || interfaces.length == 0) {
            list = new String[]{setterIntf};
        } else {
            list = new String[interfaces.length + 1];
            for (int i = 0; i < interfaces.length; i++) {
                list[i] = interfaces[i].getName();
            }
            list[interfaces.length] = setterIntf;
        }
        cf.setInterfaces(list);
    }

    private static void addClassInitializer(ClassFile cf, ConstPool cp, String classname, int size, List<Find2MethodsArgs> forwarders) throws CannotCompileException {
        FieldInfo finfo = new FieldInfo(cp, HOLDER, HOLDER_TYPE);
        finfo.setAccessFlags(10);
        cf.addField(finfo);
        MethodInfo minfo = new MethodInfo(cp, MethodInfo.nameClinit, "()V");
        minfo.setAccessFlags(8);
        setThrows(minfo, cp, new Class[]{ClassNotFoundException.class});
        Bytecode code = new Bytecode(cp, 0, 2);
        code.addIconst(size * 2);
        code.addAnewarray("java.lang.reflect.Method");
        code.addAstore(0);
        code.addLdc(classname);
        code.addInvokestatic("java.lang.Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;");
        code.addAstore(1);
        for (Find2MethodsArgs args : forwarders) {
            callFind2Methods(code, args.methodName, args.delegatorName, args.origIndex, args.descriptor, 1, 0);
        }
        code.addAload(0);
        code.addPutstatic(classname, HOLDER, HOLDER_TYPE);
        code.addLconst(SERIAL_VERSION_UID_VALUE);
        code.addPutstatic(classname, SERIAL_VERSION_UID_FIELD, SERIAL_VERSION_UID_TYPE);
        code.addOpcode(Opcode.RETURN);
        minfo.setCodeAttribute(code.toCodeAttribute());
        cf.addMethod(minfo);
    }

    private static void callFind2Methods(Bytecode code, String superMethod, String thisMethod, int index, String desc, int classVar, int arrayVar) {
        String findClass = RuntimeSupport.class.getName();
        code.addAload(classVar);
        code.addLdc(superMethod);
        if (thisMethod == null) {
            code.addOpcode(1);
        } else {
            code.addLdc(thisMethod);
        }
        code.addIconst(index);
        code.addLdc(desc);
        code.addAload(arrayVar);
        code.addInvokestatic(findClass, "find2Methods", "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;[Ljava/lang/reflect/Method;)V");
    }

    private static void addSetter(String classname, ClassFile cf, ConstPool cp) throws CannotCompileException {
        MethodInfo minfo = new MethodInfo(cp, HANDLER_SETTER, HANDLER_SETTER_TYPE);
        minfo.setAccessFlags(1);
        Bytecode code = new Bytecode(cp, 2, 2);
        code.addAload(0);
        code.addAload(1);
        code.addPutfield(classname, HANDLER, HANDLER_TYPE);
        code.addOpcode(Opcode.RETURN);
        minfo.setCodeAttribute(code.toCodeAttribute());
        cf.addMethod(minfo);
    }

    private static void addGetter(String classname, ClassFile cf, ConstPool cp) throws CannotCompileException {
        MethodInfo minfo = new MethodInfo(cp, HANDLER_GETTER, HANDLER_GETTER_TYPE);
        minfo.setAccessFlags(1);
        Bytecode code = new Bytecode(cp, 1, 1);
        code.addAload(0);
        code.addGetfield(classname, HANDLER, HANDLER_TYPE);
        code.addOpcode(Opcode.ARETURN);
        minfo.setCodeAttribute(code.toCodeAttribute());
        cf.addMethod(minfo);
    }

    private int overrideMethods(ClassFile cf, ConstPool cp, String className, List<Find2MethodsArgs> forwarders) throws CannotCompileException {
        String prefix = makeUniqueName("_d", this.signatureMethods);
        int index = 0;
        for (Map.Entry<String, Method> e : this.signatureMethods) {
            if ((ClassFile.MAJOR_VERSION < 49 || !isBridge(e.getValue())) && testBit(this.signature, index)) {
                override(className, e.getValue(), prefix, index, keyToDesc(e.getKey(), e.getValue()), cf, cp, forwarders);
            }
            index++;
        }
        return index;
    }

    private static boolean isBridge(Method m) {
        return m.isBridge();
    }

    private void override(String thisClassname, Method meth, String prefix, int index, String desc, ClassFile cf, ConstPool cp, List<Find2MethodsArgs> forwarders) throws CannotCompileException {
        Class<?> declClass = meth.getDeclaringClass();
        String delegatorName = prefix + index + meth.getName();
        if (Modifier.isAbstract(meth.getModifiers())) {
            delegatorName = null;
        } else {
            MethodInfo delegator = makeDelegator(meth, desc, cp, declClass, delegatorName);
            delegator.setAccessFlags(delegator.getAccessFlags() & (-65));
            cf.addMethod(delegator);
        }
        MethodInfo forwarder = makeForwarder(thisClassname, meth, desc, cp, declClass, delegatorName, index, forwarders);
        cf.addMethod(forwarder);
    }

    private void makeConstructors(String thisClassName, ClassFile cf, ConstPool cp, String classname) throws CannotCompileException {
        Constructor<?>[] cons = SecurityActions.getDeclaredConstructors(this.superClass);
        boolean doHandlerInit = !this.factoryUseCache;
        for (Constructor<?> c : cons) {
            int mod = c.getModifiers();
            if (!Modifier.isFinal(mod) && !Modifier.isPrivate(mod) && isVisible(mod, this.basename, c)) {
                MethodInfo m = makeConstructor(thisClassName, c, cp, this.superClass, doHandlerInit);
                cf.addMethod(m);
            }
        }
    }

    private static String makeUniqueName(String name, List<Map.Entry<String, Method>> sortedMethods) {
        if (makeUniqueName0(name, sortedMethods.iterator())) {
            return name;
        }
        for (int i = 100; i < 999; i++) {
            String s = name + i;
            if (makeUniqueName0(s, sortedMethods.iterator())) {
                return s;
            }
        }
        throw new RuntimeException("cannot make a unique method name");
    }

    private static boolean makeUniqueName0(String name, Iterator<Map.Entry<String, Method>> it) {
        while (it.hasNext()) {
            if (it.next().getKey().startsWith(name)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isVisible(int mod, String from, Member meth) {
        if ((mod & 2) != 0) {
            return false;
        }
        if ((mod & 5) != 0) {
            return true;
        }
        String p = getPackageName(from);
        String q = getPackageName(meth.getDeclaringClass().getName());
        if (p == null) {
            return q == null;
        }
        return p.equals(q);
    }

    private static String getPackageName(String name) {
        int i = name.lastIndexOf(46);
        if (i < 0) {
            return null;
        }
        return name.substring(0, i);
    }

    private Map<String, Method> getMethods(Class<?> superClass, Class<?>[] interfaceTypes) {
        Map<String, Method> hash = new HashMap<>();
        Set<Class<?>> set = new HashSet<>();
        for (Class<?> cls : interfaceTypes) {
            getMethods(hash, cls, set);
        }
        getMethods(hash, superClass, set);
        return hash;
    }

    private void getMethods(Map<String, Method> hash, Class<?> clazz, Set<Class<?>> visitedClasses) {
        if (!visitedClasses.add(clazz)) {
            return;
        }
        Class<?>[] ifs = clazz.getInterfaces();
        for (Class<?> cls : ifs) {
            getMethods(hash, cls, visitedClasses);
        }
        Class<?> parent = clazz.getSuperclass();
        if (parent != null) {
            getMethods(hash, parent, visitedClasses);
        }
        Method[] methods = SecurityActions.getDeclaredMethods(clazz);
        for (int i = 0; i < methods.length; i++) {
            if (!Modifier.isPrivate(methods[i].getModifiers())) {
                Method m = methods[i];
                String key = m.getName() + ':' + RuntimeSupport.makeDescriptor(m);
                if (key.startsWith(HANDLER_GETTER_KEY)) {
                    this.hasGetHandler = true;
                }
                Method oldMethod = hash.put(key, m);
                if (null != oldMethod && isBridge(m) && !Modifier.isPublic(oldMethod.getDeclaringClass().getModifiers()) && !Modifier.isAbstract(oldMethod.getModifiers()) && !isDuplicated(i, methods)) {
                    hash.put(key, oldMethod);
                }
                if (null != oldMethod && Modifier.isPublic(oldMethod.getModifiers()) && !Modifier.isPublic(m.getModifiers())) {
                    hash.put(key, oldMethod);
                }
            }
        }
    }

    private static boolean isDuplicated(int index, Method[] methods) {
        String name = methods[index].getName();
        for (int i = 0; i < methods.length; i++) {
            if (i != index && name.equals(methods[i].getName()) && areParametersSame(methods[index], methods[i])) {
                return true;
            }
        }
        return false;
    }

    private static boolean areParametersSame(Method method, Method targetMethod) {
        Class<?>[] methodTypes = method.getParameterTypes();
        Class<?>[] targetMethodTypes = targetMethod.getParameterTypes();
        if (methodTypes.length == targetMethodTypes.length) {
            for (int i = 0; i < methodTypes.length; i++) {
                if (!methodTypes[i].getName().equals(targetMethodTypes[i].getName())) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    private static String keyToDesc(String key, Method m) {
        return key.substring(key.indexOf(58) + 1);
    }

    private static MethodInfo makeConstructor(String thisClassName, Constructor<?> cons, ConstPool cp, Class<?> superClass, boolean doHandlerInit) {
        String desc = RuntimeSupport.makeDescriptor(cons.getParameterTypes(), Void.TYPE);
        MethodInfo minfo = new MethodInfo(cp, "<init>", desc);
        minfo.setAccessFlags(1);
        setThrows(minfo, cp, cons.getExceptionTypes());
        Bytecode code = new Bytecode(cp, 0, 0);
        if (doHandlerInit) {
            code.addAload(0);
            code.addGetstatic(thisClassName, DEFAULT_INTERCEPTOR, HANDLER_TYPE);
            code.addPutfield(thisClassName, HANDLER, HANDLER_TYPE);
            code.addGetstatic(thisClassName, DEFAULT_INTERCEPTOR, HANDLER_TYPE);
            code.addOpcode(Opcode.IFNONNULL);
            code.addIndex(10);
        }
        code.addAload(0);
        code.addGetstatic(NULL_INTERCEPTOR_HOLDER, DEFAULT_INTERCEPTOR, HANDLER_TYPE);
        code.addPutfield(thisClassName, HANDLER, HANDLER_TYPE);
        int pc = code.currentPc();
        code.addAload(0);
        int s = addLoadParameters(code, cons.getParameterTypes(), 1);
        code.addInvokespecial(superClass.getName(), "<init>", desc);
        code.addOpcode(Opcode.RETURN);
        code.setMaxLocals(s + 1);
        CodeAttribute ca = code.toCodeAttribute();
        minfo.setCodeAttribute(ca);
        StackMapTable.Writer writer = new StackMapTable.Writer(32);
        writer.sameFrame(pc);
        ca.setAttribute(writer.toStackMapTable(cp));
        return minfo;
    }

    private MethodInfo makeDelegator(Method meth, String desc, ConstPool cp, Class<?> declClass, String delegatorName) {
        MethodInfo delegator = new MethodInfo(cp, delegatorName, desc);
        delegator.setAccessFlags(17 | (meth.getModifiers() & (-1319)));
        setThrows(delegator, cp, meth);
        Bytecode code = new Bytecode(cp, 0, 0);
        code.addAload(0);
        int s = addLoadParameters(code, meth.getParameterTypes(), 1);
        Class<?> targetClass = invokespecialTarget(declClass);
        code.addInvokespecial(targetClass.isInterface(), cp.addClassInfo(targetClass.getName()), meth.getName(), desc);
        addReturn(code, meth.getReturnType());
        code.setMaxLocals(s + 1);
        delegator.setCodeAttribute(code.toCodeAttribute());
        return delegator;
    }

    private Class<?> invokespecialTarget(Class<?> declClass) {
        Class<?>[] clsArr;
        if (declClass.isInterface()) {
            for (Class<?> i : this.interfaces) {
                if (declClass.isAssignableFrom(i)) {
                    return i;
                }
            }
        }
        return this.superClass;
    }

    private static MethodInfo makeForwarder(String thisClassName, Method meth, String desc, ConstPool cp, Class<?> declClass, String delegatorName, int index, List<Find2MethodsArgs> forwarders) {
        MethodInfo forwarder = new MethodInfo(cp, meth.getName(), desc);
        forwarder.setAccessFlags(16 | (meth.getModifiers() & (-1313)));
        setThrows(forwarder, cp, meth);
        int args = Descriptor.paramSize(desc);
        Bytecode code = new Bytecode(cp, 0, args + 2);
        int origIndex = index * 2;
        int delIndex = (index * 2) + 1;
        int arrayVar = args + 1;
        code.addGetstatic(thisClassName, HOLDER, HOLDER_TYPE);
        code.addAstore(arrayVar);
        forwarders.add(new Find2MethodsArgs(meth.getName(), delegatorName, desc, origIndex));
        code.addAload(0);
        code.addGetfield(thisClassName, HANDLER, HANDLER_TYPE);
        code.addAload(0);
        code.addAload(arrayVar);
        code.addIconst(origIndex);
        code.addOpcode(50);
        code.addAload(arrayVar);
        code.addIconst(delIndex);
        code.addOpcode(50);
        makeParameterList(code, meth.getParameterTypes());
        code.addInvokeinterface(MethodHandler.class.getName(), "invoke", "(Ljava/lang/Object;Ljava/lang/reflect/Method;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;", 5);
        Class<?> retType = meth.getReturnType();
        addUnwrapper(code, retType);
        addReturn(code, retType);
        CodeAttribute ca = code.toCodeAttribute();
        forwarder.setCodeAttribute(ca);
        return forwarder;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:javassist/util/proxy/ProxyFactory$Find2MethodsArgs.class */
    public static class Find2MethodsArgs {
        String methodName;
        String delegatorName;
        String descriptor;
        int origIndex;

        Find2MethodsArgs(String mname, String dname, String desc, int index) {
            this.methodName = mname;
            this.delegatorName = dname;
            this.descriptor = desc;
            this.origIndex = index;
        }
    }

    private static void setThrows(MethodInfo minfo, ConstPool cp, Method orig) {
        Class<?>[] exceptions = orig.getExceptionTypes();
        setThrows(minfo, cp, exceptions);
    }

    private static void setThrows(MethodInfo minfo, ConstPool cp, Class<?>[] exceptions) {
        if (exceptions.length == 0) {
            return;
        }
        String[] list = new String[exceptions.length];
        for (int i = 0; i < exceptions.length; i++) {
            list[i] = exceptions[i].getName();
        }
        ExceptionsAttribute ea = new ExceptionsAttribute(cp);
        ea.setExceptions(list);
        minfo.setExceptionsAttribute(ea);
    }

    private static int addLoadParameters(Bytecode code, Class<?>[] params, int offset) {
        int stacksize = 0;
        for (Class<?> cls : params) {
            stacksize += addLoad(code, stacksize + offset, cls);
        }
        return stacksize;
    }

    private static int addLoad(Bytecode code, int n, Class<?> type) {
        if (type.isPrimitive()) {
            if (type == Long.TYPE) {
                code.addLload(n);
                return 2;
            } else if (type == Float.TYPE) {
                code.addFload(n);
                return 1;
            } else if (type == Double.TYPE) {
                code.addDload(n);
                return 2;
            } else {
                code.addIload(n);
                return 1;
            }
        }
        code.addAload(n);
        return 1;
    }

    private static int addReturn(Bytecode code, Class<?> type) {
        if (type.isPrimitive()) {
            if (type == Long.TYPE) {
                code.addOpcode(Opcode.LRETURN);
                return 2;
            } else if (type == Float.TYPE) {
                code.addOpcode(Opcode.FRETURN);
                return 1;
            } else if (type == Double.TYPE) {
                code.addOpcode(Opcode.DRETURN);
                return 2;
            } else if (type == Void.TYPE) {
                code.addOpcode(Opcode.RETURN);
                return 0;
            } else {
                code.addOpcode(Opcode.IRETURN);
                return 1;
            }
        }
        code.addOpcode(Opcode.ARETURN);
        return 1;
    }

    private static void makeParameterList(Bytecode code, Class<?>[] params) {
        int regno = 1;
        int n = params.length;
        code.addIconst(n);
        code.addAnewarray("java/lang/Object");
        for (int i = 0; i < n; i++) {
            code.addOpcode(89);
            code.addIconst(i);
            Class<?> type = params[i];
            if (type.isPrimitive()) {
                regno = makeWrapper(code, type, regno);
            } else {
                code.addAload(regno);
                regno++;
            }
            code.addOpcode(83);
        }
    }

    private static int makeWrapper(Bytecode code, Class<?> type, int regno) {
        int index = FactoryHelper.typeIndex(type);
        String wrapper = FactoryHelper.wrapperTypes[index];
        code.addNew(wrapper);
        code.addOpcode(89);
        addLoad(code, regno, type);
        code.addInvokespecial(wrapper, "<init>", FactoryHelper.wrapperDesc[index]);
        return regno + FactoryHelper.dataSize[index];
    }

    private static void addUnwrapper(Bytecode code, Class<?> type) {
        if (type.isPrimitive()) {
            if (type == Void.TYPE) {
                code.addOpcode(87);
                return;
            }
            int index = FactoryHelper.typeIndex(type);
            String wrapper = FactoryHelper.wrapperTypes[index];
            code.addCheckcast(wrapper);
            code.addInvokevirtual(wrapper, FactoryHelper.unwarpMethods[index], FactoryHelper.unwrapDesc[index]);
            return;
        }
        code.addCheckcast(type.getName());
    }

    private static MethodInfo makeWriteReplace(ConstPool cp) {
        MethodInfo minfo = new MethodInfo(cp, "writeReplace", "()Ljava/lang/Object;");
        String[] list = {"java.io.ObjectStreamException"};
        ExceptionsAttribute ea = new ExceptionsAttribute(cp);
        ea.setExceptions(list);
        minfo.setExceptionsAttribute(ea);
        Bytecode code = new Bytecode(cp, 0, 1);
        code.addAload(0);
        code.addInvokestatic(NULL_INTERCEPTOR_HOLDER, "makeSerializedProxy", "(Ljava/lang/Object;)Ljavassist/util/proxy/SerializedProxy;");
        code.addOpcode(Opcode.ARETURN);
        minfo.setCodeAttribute(code.toCodeAttribute());
        return minfo;
    }
}