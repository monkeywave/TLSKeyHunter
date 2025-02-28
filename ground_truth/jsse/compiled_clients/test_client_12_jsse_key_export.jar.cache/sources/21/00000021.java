package javassist;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.Reference;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javassist.CtField;
import javassist.CtMember;
import javassist.bytecode.AccessFlag;
import javassist.bytecode.AnnotationsAttribute;
import javassist.bytecode.AttributeInfo;
import javassist.bytecode.BadBytecode;
import javassist.bytecode.Bytecode;
import javassist.bytecode.ClassFile;
import javassist.bytecode.CodeAttribute;
import javassist.bytecode.CodeIterator;
import javassist.bytecode.ConstPool;
import javassist.bytecode.ConstantAttribute;
import javassist.bytecode.Descriptor;
import javassist.bytecode.EnclosingMethodAttribute;
import javassist.bytecode.FieldInfo;
import javassist.bytecode.InnerClassesAttribute;
import javassist.bytecode.MethodInfo;
import javassist.bytecode.Opcode;
import javassist.bytecode.ParameterAnnotationsAttribute;
import javassist.bytecode.SignatureAttribute;
import javassist.bytecode.annotation.Annotation;
import javassist.bytecode.annotation.AnnotationImpl;
import javassist.compiler.AccessorMaker;
import javassist.compiler.CompileError;
import javassist.compiler.Javac;
import javassist.expr.ExprEditor;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:javassist/CtClassType.class */
public class CtClassType extends CtClass {
    ClassPool classPool;
    boolean wasChanged;
    private boolean wasFrozen;
    boolean wasPruned;
    boolean gcConstPool;
    ClassFile classfile;
    byte[] rawClassfile;
    private Reference<CtMember.Cache> memberCache;
    private AccessorMaker accessors;
    private FieldInitLink fieldInitializers;
    private Map<CtMethod, String> hiddenMethods;
    private int uniqueNumberSeed;
    private boolean doPruning;
    private int getCount;
    private static final int GET_THRESHOLD = 2;

    /* JADX INFO: Access modifiers changed from: package-private */
    public CtClassType(String name, ClassPool cp) {
        super(name);
        this.doPruning = ClassPool.doPruning;
        this.classPool = cp;
        this.gcConstPool = false;
        this.wasPruned = false;
        this.wasFrozen = false;
        this.wasChanged = false;
        this.classfile = null;
        this.rawClassfile = null;
        this.memberCache = null;
        this.accessors = null;
        this.fieldInitializers = null;
        this.hiddenMethods = null;
        this.uniqueNumberSeed = 0;
        this.getCount = 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CtClassType(InputStream ins, ClassPool cp) throws IOException {
        this((String) null, cp);
        this.classfile = new ClassFile(new DataInputStream(ins));
        this.qualifiedName = this.classfile.getName();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CtClassType(ClassFile cf, ClassPool cp) {
        this((String) null, cp);
        this.classfile = cf;
        this.qualifiedName = this.classfile.getName();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // javassist.CtClass
    public void extendToString(StringBuffer buffer) {
        if (this.wasChanged) {
            buffer.append("changed ");
        }
        if (this.wasFrozen) {
            buffer.append("frozen ");
        }
        if (this.wasPruned) {
            buffer.append("pruned ");
        }
        buffer.append(Modifier.toString(getModifiers()));
        buffer.append(" class ");
        buffer.append(getName());
        try {
            CtClass ext = getSuperclass();
            if (ext != null) {
                String name = ext.getName();
                if (!name.equals("java.lang.Object")) {
                    buffer.append(" extends " + ext.getName());
                }
            }
        } catch (NotFoundException e) {
            buffer.append(" extends ??");
        }
        try {
            CtClass[] intf = getInterfaces();
            if (intf.length > 0) {
                buffer.append(" implements ");
            }
            for (CtClass ctClass : intf) {
                buffer.append(ctClass.getName());
                buffer.append(", ");
            }
        } catch (NotFoundException e2) {
            buffer.append(" extends ??");
        }
        CtMember.Cache memCache = getMembers();
        exToString(buffer, " fields=", memCache.fieldHead(), memCache.lastField());
        exToString(buffer, " constructors=", memCache.consHead(), memCache.lastCons());
        exToString(buffer, " methods=", memCache.methodHead(), memCache.lastMethod());
    }

    private void exToString(StringBuffer buffer, String msg, CtMember head, CtMember tail) {
        buffer.append(msg);
        while (head != tail) {
            head = head.next();
            buffer.append(head);
            buffer.append(", ");
        }
    }

    @Override // javassist.CtClass
    public AccessorMaker getAccessorMaker() {
        if (this.accessors == null) {
            this.accessors = new AccessorMaker(this);
        }
        return this.accessors;
    }

    @Override // javassist.CtClass
    public ClassFile getClassFile2() {
        return getClassFile3(true);
    }

    public ClassFile getClassFile3(boolean doCompress) {
        ClassFile cfile = this.classfile;
        if (cfile != null) {
            return cfile;
        }
        if (doCompress) {
            this.classPool.compress();
        }
        if (this.rawClassfile != null) {
            try {
                ClassFile cf = new ClassFile(new DataInputStream(new ByteArrayInputStream(this.rawClassfile)));
                this.rawClassfile = null;
                this.getCount = 2;
                return setClassFile(cf);
            } catch (IOException e) {
                throw new RuntimeException(e.toString(), e);
            }
        }
        InputStream fin = null;
        try {
            try {
                InputStream fin2 = this.classPool.openClassfile(getName());
                if (fin2 == null) {
                    throw new NotFoundException(getName());
                }
                InputStream fin3 = new BufferedInputStream(fin2);
                ClassFile cf2 = new ClassFile(new DataInputStream(fin3));
                if (!cf2.getName().equals(this.qualifiedName)) {
                    throw new RuntimeException("cannot find " + this.qualifiedName + ": " + cf2.getName() + " found in " + this.qualifiedName.replace('.', '/') + ".class");
                }
                ClassFile classFile = setClassFile(cf2);
                if (fin3 != null) {
                    try {
                        fin3.close();
                    } catch (IOException e2) {
                    }
                }
                return classFile;
            } catch (IOException e3) {
                throw new RuntimeException(e3.toString(), e3);
            } catch (NotFoundException e4) {
                throw new RuntimeException(e4.toString(), e4);
            }
        } catch (Throwable th) {
            if (0 != 0) {
                try {
                    fin.close();
                } catch (IOException e5) {
                }
            }
            throw th;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // javassist.CtClass
    public final void incGetCounter() {
        this.getCount++;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // javassist.CtClass
    public void compress() {
        if (this.getCount < 2) {
            if (!isModified() && ClassPool.releaseUnmodifiedClassFile) {
                removeClassFile();
            } else if (isFrozen() && !this.wasPruned) {
                saveClassFile();
            }
        }
        this.getCount = 0;
    }

    private synchronized void saveClassFile() {
        if (this.classfile == null || hasMemberCache() != null) {
            return;
        }
        ByteArrayOutputStream barray = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(barray);
        try {
            this.classfile.write(out);
            barray.close();
            this.rawClassfile = barray.toByteArray();
            this.classfile = null;
        } catch (IOException e) {
        }
    }

    private synchronized void removeClassFile() {
        if (this.classfile != null && !isModified() && hasMemberCache() == null) {
            this.classfile = null;
        }
    }

    private synchronized ClassFile setClassFile(ClassFile cf) {
        if (this.classfile == null) {
            this.classfile = cf;
        }
        return this.classfile;
    }

    @Override // javassist.CtClass
    public ClassPool getClassPool() {
        return this.classPool;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setClassPool(ClassPool cp) {
        this.classPool = cp;
    }

    @Override // javassist.CtClass
    public URL getURL() throws NotFoundException {
        URL url = this.classPool.find(getName());
        if (url == null) {
            throw new NotFoundException(getName());
        }
        return url;
    }

    @Override // javassist.CtClass
    public boolean isModified() {
        return this.wasChanged;
    }

    @Override // javassist.CtClass
    public boolean isFrozen() {
        return this.wasFrozen;
    }

    @Override // javassist.CtClass
    public void freeze() {
        this.wasFrozen = true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // javassist.CtClass
    public void checkModify() throws RuntimeException {
        if (isFrozen()) {
            String msg = getName() + " class is frozen";
            if (this.wasPruned) {
                msg = msg + " and pruned";
            }
            throw new RuntimeException(msg);
        }
        this.wasChanged = true;
    }

    @Override // javassist.CtClass
    public void defrost() {
        checkPruned("defrost");
        this.wasFrozen = false;
    }

    @Override // javassist.CtClass
    public boolean subtypeOf(CtClass clazz) throws NotFoundException {
        String cname = clazz.getName();
        if (this == clazz || getName().equals(cname)) {
            return true;
        }
        ClassFile file = getClassFile2();
        String supername = file.getSuperclass();
        if (supername != null && supername.equals(cname)) {
            return true;
        }
        String[] ifs = file.getInterfaces();
        for (String str : ifs) {
            if (str.equals(cname)) {
                return true;
            }
        }
        if (supername != null && this.classPool.get(supername).subtypeOf(clazz)) {
            return true;
        }
        for (String str2 : ifs) {
            if (this.classPool.get(str2).subtypeOf(clazz)) {
                return true;
            }
        }
        return false;
    }

    @Override // javassist.CtClass
    public void setName(String name) throws RuntimeException {
        String oldname = getName();
        if (name.equals(oldname)) {
            return;
        }
        this.classPool.checkNotFrozen(name);
        ClassFile cf = getClassFile2();
        super.setName(name);
        cf.setName(name);
        nameReplaced();
        this.classPool.classNameChanged(oldname, this);
    }

    @Override // javassist.CtClass
    public String getGenericSignature() {
        SignatureAttribute sa = (SignatureAttribute) getClassFile2().getAttribute(SignatureAttribute.tag);
        if (sa == null) {
            return null;
        }
        return sa.getSignature();
    }

    @Override // javassist.CtClass
    public void setGenericSignature(String sig) {
        ClassFile cf = getClassFile();
        SignatureAttribute sa = new SignatureAttribute(cf.getConstPool(), sig);
        cf.addAttribute(sa);
    }

    @Override // javassist.CtClass
    public void replaceClassName(ClassMap classnames) throws RuntimeException {
        String oldClassName = getName();
        String newClassName = classnames.get((Object) Descriptor.toJvmName(oldClassName));
        if (newClassName != null) {
            newClassName = Descriptor.toJavaName(newClassName);
            this.classPool.checkNotFrozen(newClassName);
        }
        super.replaceClassName(classnames);
        ClassFile cf = getClassFile2();
        cf.renameClass(classnames);
        nameReplaced();
        if (newClassName != null) {
            super.setName(newClassName);
            this.classPool.classNameChanged(oldClassName, this);
        }
    }

    @Override // javassist.CtClass
    public void replaceClassName(String oldname, String newname) throws RuntimeException {
        String thisname = getName();
        if (thisname.equals(oldname)) {
            setName(newname);
            return;
        }
        super.replaceClassName(oldname, newname);
        getClassFile2().renameClass(oldname, newname);
        nameReplaced();
    }

    @Override // javassist.CtClass
    public boolean isInterface() {
        return Modifier.isInterface(getModifiers());
    }

    @Override // javassist.CtClass
    public boolean isAnnotation() {
        return Modifier.isAnnotation(getModifiers());
    }

    @Override // javassist.CtClass
    public boolean isEnum() {
        return Modifier.isEnum(getModifiers());
    }

    @Override // javassist.CtClass
    public int getModifiers() {
        ClassFile cf = getClassFile2();
        int acc = AccessFlag.clear(cf.getAccessFlags(), 32);
        int inner = cf.getInnerAccessFlags();
        if (inner != -1) {
            if ((inner & 8) != 0) {
                acc |= 8;
            }
            if ((inner & 1) != 0) {
                acc |= 1;
            } else {
                acc &= -2;
                if ((inner & 4) != 0) {
                    acc |= 4;
                } else if ((inner & 2) != 0) {
                    acc |= 2;
                }
            }
        }
        return AccessFlag.toModifier(acc);
    }

    @Override // javassist.CtClass
    public CtClass[] getNestedClasses() throws NotFoundException {
        ClassFile cf = getClassFile2();
        InnerClassesAttribute ica = (InnerClassesAttribute) cf.getAttribute(InnerClassesAttribute.tag);
        if (ica == null) {
            return new CtClass[0];
        }
        String thisName = cf.getName() + "$";
        int n = ica.tableLength();
        List<CtClass> list = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            String name = ica.innerClass(i);
            if (name != null && name.startsWith(thisName) && name.lastIndexOf(36) < thisName.length()) {
                list.add(this.classPool.get(name));
            }
        }
        return (CtClass[]) list.toArray(new CtClass[list.size()]);
    }

    @Override // javassist.CtClass
    public void setModifiers(int mod) {
        checkModify();
        updateInnerEntry(mod, getName(), this, true);
        ClassFile cf = getClassFile2();
        cf.setAccessFlags(AccessFlag.m131of(mod & (-9)));
    }

    private static void updateInnerEntry(int newMod, String name, CtClass clazz, boolean outer) {
        int isStatic;
        ClassFile cf = clazz.getClassFile2();
        InnerClassesAttribute ica = (InnerClassesAttribute) cf.getAttribute(InnerClassesAttribute.tag);
        if (ica != null) {
            int mod = newMod & (-9);
            int i = ica.find(name);
            if (i >= 0 && ((isStatic = ica.accessFlags(i) & 8) != 0 || !Modifier.isStatic(newMod))) {
                clazz.checkModify();
                ica.setAccessFlags(i, AccessFlag.m131of(mod) | isStatic);
                String outName = ica.outerClass(i);
                if (outName != null && outer) {
                    try {
                        CtClass parent = clazz.getClassPool().get(outName);
                        updateInnerEntry(mod, name, parent, false);
                        return;
                    } catch (NotFoundException e) {
                        throw new RuntimeException("cannot find the declaring class: " + outName);
                    }
                }
                return;
            }
        }
        if (Modifier.isStatic(newMod)) {
            throw new RuntimeException("cannot change " + Descriptor.toJavaName(name) + " into a static class");
        }
    }

    @Override // javassist.CtClass
    public boolean hasAnnotation(String annotationName) {
        ClassFile cf = getClassFile2();
        AnnotationsAttribute ainfo = (AnnotationsAttribute) cf.getAttribute(AnnotationsAttribute.invisibleTag);
        AnnotationsAttribute ainfo2 = (AnnotationsAttribute) cf.getAttribute(AnnotationsAttribute.visibleTag);
        return hasAnnotationType(annotationName, getClassPool(), ainfo, ainfo2);
    }

    @Deprecated
    static boolean hasAnnotationType(Class<?> clz, ClassPool cp, AnnotationsAttribute a1, AnnotationsAttribute a2) {
        return hasAnnotationType(clz.getName(), cp, a1, a2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean hasAnnotationType(String annotationTypeName, ClassPool cp, AnnotationsAttribute a1, AnnotationsAttribute a2) {
        Annotation[] anno1;
        Annotation[] anno2;
        if (a1 == null) {
            anno1 = null;
        } else {
            anno1 = a1.getAnnotations();
        }
        if (a2 == null) {
            anno2 = null;
        } else {
            anno2 = a2.getAnnotations();
        }
        if (anno1 != null) {
            for (Annotation annotation : anno1) {
                if (annotation.getTypeName().equals(annotationTypeName)) {
                    return true;
                }
            }
        }
        if (anno2 != null) {
            for (Annotation annotation2 : anno2) {
                if (annotation2.getTypeName().equals(annotationTypeName)) {
                    return true;
                }
            }
            return false;
        }
        return false;
    }

    @Override // javassist.CtClass
    public Object getAnnotation(Class<?> clz) throws ClassNotFoundException {
        ClassFile cf = getClassFile2();
        AnnotationsAttribute ainfo = (AnnotationsAttribute) cf.getAttribute(AnnotationsAttribute.invisibleTag);
        AnnotationsAttribute ainfo2 = (AnnotationsAttribute) cf.getAttribute(AnnotationsAttribute.visibleTag);
        return getAnnotationType(clz, getClassPool(), ainfo, ainfo2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Object getAnnotationType(Class<?> clz, ClassPool cp, AnnotationsAttribute a1, AnnotationsAttribute a2) throws ClassNotFoundException {
        Annotation[] anno1;
        Annotation[] anno2;
        if (a1 == null) {
            anno1 = null;
        } else {
            anno1 = a1.getAnnotations();
        }
        if (a2 == null) {
            anno2 = null;
        } else {
            anno2 = a2.getAnnotations();
        }
        String typeName = clz.getName();
        if (anno1 != null) {
            for (int i = 0; i < anno1.length; i++) {
                if (anno1[i].getTypeName().equals(typeName)) {
                    return toAnnoType(anno1[i], cp);
                }
            }
        }
        if (anno2 != null) {
            for (int i2 = 0; i2 < anno2.length; i2++) {
                if (anno2[i2].getTypeName().equals(typeName)) {
                    return toAnnoType(anno2[i2], cp);
                }
            }
            return null;
        }
        return null;
    }

    @Override // javassist.CtClass
    public Object[] getAnnotations() throws ClassNotFoundException {
        return getAnnotations(false);
    }

    @Override // javassist.CtClass
    public Object[] getAvailableAnnotations() {
        try {
            return getAnnotations(true);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("Unexpected exception ", e);
        }
    }

    private Object[] getAnnotations(boolean ignoreNotFound) throws ClassNotFoundException {
        ClassFile cf = getClassFile2();
        AnnotationsAttribute ainfo = (AnnotationsAttribute) cf.getAttribute(AnnotationsAttribute.invisibleTag);
        AnnotationsAttribute ainfo2 = (AnnotationsAttribute) cf.getAttribute(AnnotationsAttribute.visibleTag);
        return toAnnotationType(ignoreNotFound, getClassPool(), ainfo, ainfo2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Object[] toAnnotationType(boolean ignoreNotFound, ClassPool cp, AnnotationsAttribute a1, AnnotationsAttribute a2) throws ClassNotFoundException {
        Annotation[] anno1;
        int size1;
        Annotation[] anno2;
        int size2;
        if (a1 == null) {
            anno1 = null;
            size1 = 0;
        } else {
            anno1 = a1.getAnnotations();
            size1 = anno1.length;
        }
        if (a2 == null) {
            anno2 = null;
            size2 = 0;
        } else {
            anno2 = a2.getAnnotations();
            size2 = anno2.length;
        }
        if (!ignoreNotFound) {
            Object[] result = new Object[size1 + size2];
            for (int i = 0; i < size1; i++) {
                result[i] = toAnnoType(anno1[i], cp);
            }
            for (int j = 0; j < size2; j++) {
                result[j + size1] = toAnnoType(anno2[j], cp);
            }
            return result;
        }
        List<Object> annotations = new ArrayList<>();
        for (int i2 = 0; i2 < size1; i2++) {
            try {
                annotations.add(toAnnoType(anno1[i2], cp));
            } catch (ClassNotFoundException e) {
            }
        }
        for (int j2 = 0; j2 < size2; j2++) {
            try {
                annotations.add(toAnnoType(anno2[j2], cp));
            } catch (ClassNotFoundException e2) {
            }
        }
        return annotations.toArray();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v9, types: [java.lang.Object[], java.lang.Object[][]] */
    public static Object[][] toAnnotationType(boolean ignoreNotFound, ClassPool cp, ParameterAnnotationsAttribute a1, ParameterAnnotationsAttribute a2, MethodInfo minfo) throws ClassNotFoundException {
        int numParameters;
        Annotation[] anno1;
        int size1;
        Annotation[] anno2;
        int size2;
        if (a1 != null) {
            numParameters = a1.numParameters();
        } else if (a2 != null) {
            numParameters = a2.numParameters();
        } else {
            numParameters = Descriptor.numOfParameters(minfo.getDescriptor());
        }
        ?? r0 = new Object[numParameters];
        for (int i = 0; i < numParameters; i++) {
            if (a1 == null) {
                anno1 = null;
                size1 = 0;
            } else {
                anno1 = a1.getAnnotations()[i];
                size1 = anno1.length;
            }
            if (a2 == null) {
                anno2 = null;
                size2 = 0;
            } else {
                anno2 = a2.getAnnotations()[i];
                size2 = anno2.length;
            }
            if (!ignoreNotFound) {
                r0[i] = new Object[size1 + size2];
                for (int j = 0; j < size1; j++) {
                    r0[i][j] = toAnnoType(anno1[j], cp);
                }
                for (int j2 = 0; j2 < size2; j2++) {
                    r0[i][j2 + size1] = toAnnoType(anno2[j2], cp);
                }
            } else {
                List<Object> annotations = new ArrayList<>();
                for (int j3 = 0; j3 < size1; j3++) {
                    try {
                        annotations.add(toAnnoType(anno1[j3], cp));
                    } catch (ClassNotFoundException e) {
                    }
                }
                for (int j4 = 0; j4 < size2; j4++) {
                    try {
                        annotations.add(toAnnoType(anno2[j4], cp));
                    } catch (ClassNotFoundException e2) {
                    }
                }
                r0[i] = annotations.toArray();
            }
        }
        return r0;
    }

    private static Object toAnnoType(Annotation anno, ClassPool cp) throws ClassNotFoundException {
        try {
            ClassLoader cl = cp.getClassLoader();
            return anno.toAnnotationType(cl, cp);
        } catch (ClassNotFoundException e) {
            ClassLoader cl2 = cp.getClass().getClassLoader();
            try {
                return anno.toAnnotationType(cl2, cp);
            } catch (ClassNotFoundException e2) {
                try {
                    Class<?> clazz = cp.get(anno.getTypeName()).toClass();
                    return AnnotationImpl.make(clazz.getClassLoader(), clazz, cp, anno);
                } catch (Throwable th) {
                    throw new ClassNotFoundException(anno.getTypeName());
                }
            }
        }
    }

    @Override // javassist.CtClass
    public boolean subclassOf(CtClass superclass) {
        if (superclass == null) {
            return false;
        }
        String superName = superclass.getName();
        for (CtClass curr = this; curr != null; curr = curr.getSuperclass()) {
            try {
                if (curr.getName().equals(superName)) {
                    return true;
                }
            } catch (Exception e) {
                return false;
            }
        }
        return false;
    }

    @Override // javassist.CtClass
    public CtClass getSuperclass() throws NotFoundException {
        String supername = getClassFile2().getSuperclass();
        if (supername == null) {
            return null;
        }
        return this.classPool.get(supername);
    }

    @Override // javassist.CtClass
    public void setSuperclass(CtClass clazz) throws CannotCompileException {
        checkModify();
        if (isInterface()) {
            addInterface(clazz);
        } else {
            getClassFile2().setSuperclass(clazz.getName());
        }
    }

    @Override // javassist.CtClass
    public CtClass[] getInterfaces() throws NotFoundException {
        String[] ifs = getClassFile2().getInterfaces();
        int num = ifs.length;
        CtClass[] ifc = new CtClass[num];
        for (int i = 0; i < num; i++) {
            ifc[i] = this.classPool.get(ifs[i]);
        }
        return ifc;
    }

    @Override // javassist.CtClass
    public void setInterfaces(CtClass[] list) {
        String[] ifs;
        checkModify();
        if (list == null) {
            ifs = new String[0];
        } else {
            int num = list.length;
            ifs = new String[num];
            for (int i = 0; i < num; i++) {
                ifs[i] = list[i].getName();
            }
        }
        getClassFile2().setInterfaces(ifs);
    }

    @Override // javassist.CtClass
    public void addInterface(CtClass anInterface) {
        checkModify();
        if (anInterface != null) {
            getClassFile2().addInterface(anInterface.getName());
        }
    }

    @Override // javassist.CtClass
    public CtClass getDeclaringClass() throws NotFoundException {
        ClassFile cf = getClassFile2();
        InnerClassesAttribute ica = (InnerClassesAttribute) cf.getAttribute(InnerClassesAttribute.tag);
        if (ica == null) {
            return null;
        }
        String name = getName();
        int n = ica.tableLength();
        for (int i = 0; i < n; i++) {
            if (name.equals(ica.innerClass(i))) {
                String outName = ica.outerClass(i);
                if (outName != null) {
                    return this.classPool.get(outName);
                }
                EnclosingMethodAttribute ema = (EnclosingMethodAttribute) cf.getAttribute(EnclosingMethodAttribute.tag);
                if (ema != null) {
                    return this.classPool.get(ema.className());
                }
            }
        }
        return null;
    }

    @Override // javassist.CtClass
    public CtBehavior getEnclosingBehavior() throws NotFoundException {
        ClassFile cf = getClassFile2();
        EnclosingMethodAttribute ema = (EnclosingMethodAttribute) cf.getAttribute(EnclosingMethodAttribute.tag);
        if (ema == null) {
            return null;
        }
        CtClass enc = this.classPool.get(ema.className());
        String name = ema.methodName();
        if ("<init>".equals(name)) {
            return enc.getConstructor(ema.methodDescriptor());
        }
        if (MethodInfo.nameClinit.equals(name)) {
            return enc.getClassInitializer();
        }
        return enc.getMethod(name, ema.methodDescriptor());
    }

    @Override // javassist.CtClass
    public CtClass makeNestedClass(String name, boolean isStatic) {
        if (!isStatic) {
            throw new RuntimeException("sorry, only nested static class is supported");
        }
        checkModify();
        CtClass c = this.classPool.makeNestedClass(getName() + "$" + name);
        ClassFile cf = getClassFile2();
        ClassFile cf2 = c.getClassFile2();
        InnerClassesAttribute ica = (InnerClassesAttribute) cf.getAttribute(InnerClassesAttribute.tag);
        if (ica == null) {
            ica = new InnerClassesAttribute(cf.getConstPool());
            cf.addAttribute(ica);
        }
        ica.append(c.getName(), getName(), name, (cf2.getAccessFlags() & (-33)) | 8);
        cf2.addAttribute(ica.copy(cf2.getConstPool(), null));
        return c;
    }

    private void nameReplaced() {
        CtMember.Cache cache = hasMemberCache();
        if (cache != null) {
            CtMember mth = cache.methodHead();
            CtMember tail = cache.lastMethod();
            while (mth != tail) {
                mth = mth.next();
                mth.nameReplaced();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public CtMember.Cache hasMemberCache() {
        if (this.memberCache != null) {
            return this.memberCache.get();
        }
        return null;
    }

    /* JADX WARN: Code restructure failed: missing block: B:5:0x0015, code lost:
        if (r0 == null) goto L8;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    protected synchronized javassist.CtMember.Cache getMembers() {
        /*
            r5 = this;
            r0 = 0
            r6 = r0
            r0 = r5
            java.lang.ref.Reference<javassist.CtMember$Cache> r0 = r0.memberCache
            if (r0 == 0) goto L18
            r0 = r5
            java.lang.ref.Reference<javassist.CtMember$Cache> r0 = r0.memberCache
            java.lang.Object r0 = r0.get()
            javassist.CtMember$Cache r0 = (javassist.CtMember.Cache) r0
            r1 = r0
            r6 = r1
            if (r0 != 0) goto L37
        L18:
            javassist.CtMember$Cache r0 = new javassist.CtMember$Cache
            r1 = r0
            r2 = r5
            r1.<init>(r2)
            r6 = r0
            r0 = r5
            r1 = r6
            r0.makeFieldCache(r1)
            r0 = r5
            r1 = r6
            r0.makeBehaviorCache(r1)
            r0 = r5
            java.lang.ref.WeakReference r1 = new java.lang.ref.WeakReference
            r2 = r1
            r3 = r6
            r2.<init>(r3)
            r0.memberCache = r1
        L37:
            r0 = r6
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: javassist.CtClassType.getMembers():javassist.CtMember$Cache");
    }

    private void makeFieldCache(CtMember.Cache cache) {
        List<FieldInfo> fields = getClassFile3(false).getFields();
        for (FieldInfo finfo : fields) {
            cache.addField(new CtField(finfo, this));
        }
    }

    private void makeBehaviorCache(CtMember.Cache cache) {
        List<MethodInfo> methods = getClassFile3(false).getMethods();
        for (MethodInfo minfo : methods) {
            if (minfo.isMethod()) {
                cache.addMethod(new CtMethod(minfo, this));
            } else {
                cache.addConstructor(new CtConstructor(minfo, this));
            }
        }
    }

    @Override // javassist.CtClass
    public CtField[] getFields() {
        List<CtMember> alist = new ArrayList<>();
        getFields(alist, this);
        return (CtField[]) alist.toArray(new CtField[alist.size()]);
    }

    private static void getFields(List<CtMember> alist, CtClass cc) {
        if (cc == null) {
            return;
        }
        try {
            getFields(alist, cc.getSuperclass());
        } catch (NotFoundException e) {
        }
        try {
            CtClass[] ifs = cc.getInterfaces();
            for (CtClass ctc : ifs) {
                getFields(alist, ctc);
            }
        } catch (NotFoundException e2) {
        }
        CtMember.Cache memCache = ((CtClassType) cc).getMembers();
        CtMember field = memCache.fieldHead();
        CtMember tail = memCache.lastField();
        while (field != tail) {
            field = field.next();
            if (!Modifier.isPrivate(field.getModifiers())) {
                alist.add(field);
            }
        }
    }

    @Override // javassist.CtClass
    public CtField getField(String name, String desc) throws NotFoundException {
        CtField f = getField2(name, desc);
        return checkGetField(f, name, desc);
    }

    private CtField checkGetField(CtField f, String name, String desc) throws NotFoundException {
        if (f == null) {
            String msg = "field: " + name;
            if (desc != null) {
                msg = msg + " type " + desc;
            }
            throw new NotFoundException(msg + " in " + getName());
        }
        return f;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // javassist.CtClass
    public CtField getField2(String name, String desc) {
        CtField df = getDeclaredField2(name, desc);
        if (df != null) {
            return df;
        }
        try {
            CtClass[] ifs = getInterfaces();
            for (CtClass ctc : ifs) {
                CtField f = ctc.getField2(name, desc);
                if (f != null) {
                    return f;
                }
            }
            CtClass s = getSuperclass();
            if (s != null) {
                return s.getField2(name, desc);
            }
            return null;
        } catch (NotFoundException e) {
            return null;
        }
    }

    @Override // javassist.CtClass
    public CtField[] getDeclaredFields() {
        CtMember.Cache memCache = getMembers();
        CtMember field = memCache.fieldHead();
        CtMember tail = memCache.lastField();
        int num = CtMember.Cache.count(field, tail);
        CtField[] cfs = new CtField[num];
        int i = 0;
        while (field != tail) {
            field = field.next();
            int i2 = i;
            i++;
            cfs[i2] = (CtField) field;
        }
        return cfs;
    }

    @Override // javassist.CtClass
    public CtField getDeclaredField(String name) throws NotFoundException {
        return getDeclaredField(name, null);
    }

    @Override // javassist.CtClass
    public CtField getDeclaredField(String name, String desc) throws NotFoundException {
        CtField f = getDeclaredField2(name, desc);
        return checkGetField(f, name, desc);
    }

    private CtField getDeclaredField2(String name, String desc) {
        CtMember.Cache memCache = getMembers();
        CtMember field = memCache.fieldHead();
        CtMember tail = memCache.lastField();
        while (field != tail) {
            field = field.next();
            if (field.getName().equals(name) && (desc == null || desc.equals(field.getSignature()))) {
                return (CtField) field;
            }
        }
        return null;
    }

    @Override // javassist.CtClass
    public CtBehavior[] getDeclaredBehaviors() {
        CtMember.Cache memCache = getMembers();
        CtMember cons = memCache.consHead();
        CtMember consTail = memCache.lastCons();
        int cnum = CtMember.Cache.count(cons, consTail);
        CtMember mth = memCache.methodHead();
        CtMember mthTail = memCache.lastMethod();
        int mnum = CtMember.Cache.count(mth, mthTail);
        CtBehavior[] cb = new CtBehavior[cnum + mnum];
        int i = 0;
        while (cons != consTail) {
            cons = cons.next();
            int i2 = i;
            i++;
            cb[i2] = (CtBehavior) cons;
        }
        while (mth != mthTail) {
            mth = mth.next();
            int i3 = i;
            i++;
            cb[i3] = (CtBehavior) mth;
        }
        return cb;
    }

    @Override // javassist.CtClass
    public CtConstructor[] getConstructors() {
        CtMember.Cache memCache = getMembers();
        CtMember cons = memCache.consHead();
        CtMember consTail = memCache.lastCons();
        int n = 0;
        CtMember mem = cons;
        while (mem != consTail) {
            mem = mem.next();
            if (isPubCons((CtConstructor) mem)) {
                n++;
            }
        }
        CtConstructor[] result = new CtConstructor[n];
        int i = 0;
        CtMember mem2 = cons;
        while (mem2 != consTail) {
            mem2 = mem2.next();
            CtConstructor cc = (CtConstructor) mem2;
            if (isPubCons(cc)) {
                int i2 = i;
                i++;
                result[i2] = cc;
            }
        }
        return result;
    }

    private static boolean isPubCons(CtConstructor cons) {
        return !Modifier.isPrivate(cons.getModifiers()) && cons.isConstructor();
    }

    @Override // javassist.CtClass
    public CtConstructor getConstructor(String desc) throws NotFoundException {
        CtMember.Cache memCache = getMembers();
        CtMember cons = memCache.consHead();
        CtMember consTail = memCache.lastCons();
        while (cons != consTail) {
            cons = cons.next();
            CtConstructor cc = (CtConstructor) cons;
            if (cc.getMethodInfo2().getDescriptor().equals(desc) && cc.isConstructor()) {
                return cc;
            }
        }
        return super.getConstructor(desc);
    }

    @Override // javassist.CtClass
    public CtConstructor[] getDeclaredConstructors() {
        CtMember.Cache memCache = getMembers();
        CtMember cons = memCache.consHead();
        CtMember consTail = memCache.lastCons();
        int n = 0;
        CtMember mem = cons;
        while (mem != consTail) {
            mem = mem.next();
            if (((CtConstructor) mem).isConstructor()) {
                n++;
            }
        }
        CtConstructor[] result = new CtConstructor[n];
        int i = 0;
        CtMember mem2 = cons;
        while (mem2 != consTail) {
            mem2 = mem2.next();
            CtConstructor cc = (CtConstructor) mem2;
            if (cc.isConstructor()) {
                int i2 = i;
                i++;
                result[i2] = cc;
            }
        }
        return result;
    }

    @Override // javassist.CtClass
    public CtConstructor getClassInitializer() {
        CtMember.Cache memCache = getMembers();
        CtMember cons = memCache.consHead();
        CtMember consTail = memCache.lastCons();
        while (cons != consTail) {
            cons = cons.next();
            CtConstructor cc = (CtConstructor) cons;
            if (cc.isClassInitializer()) {
                return cc;
            }
        }
        return null;
    }

    @Override // javassist.CtClass
    public CtMethod[] getMethods() {
        Map<String, CtMember> h = new HashMap<>();
        getMethods0(h, this);
        return (CtMethod[]) h.values().toArray(new CtMethod[h.size()]);
    }

    private static void getMethods0(Map<String, CtMember> h, CtClass cc) {
        try {
            CtClass[] ifs = cc.getInterfaces();
            for (CtClass ctc : ifs) {
                getMethods0(h, ctc);
            }
        } catch (NotFoundException e) {
        }
        try {
            CtClass s = cc.getSuperclass();
            if (s != null) {
                getMethods0(h, s);
            }
        } catch (NotFoundException e2) {
        }
        if (cc instanceof CtClassType) {
            CtMember.Cache memCache = ((CtClassType) cc).getMembers();
            CtMember mth = memCache.methodHead();
            CtMember mthTail = memCache.lastMethod();
            while (mth != mthTail) {
                mth = mth.next();
                if (!Modifier.isPrivate(mth.getModifiers())) {
                    h.put(((CtMethod) mth).getStringRep(), mth);
                }
            }
        }
    }

    @Override // javassist.CtClass
    public CtMethod getMethod(String name, String desc) throws NotFoundException {
        CtMethod m = getMethod0(this, name, desc);
        if (m != null) {
            return m;
        }
        throw new NotFoundException(name + "(..) is not found in " + getName());
    }

    private static CtMethod getMethod0(CtClass cc, String name, String desc) {
        if (cc instanceof CtClassType) {
            CtMember.Cache memCache = ((CtClassType) cc).getMembers();
            CtMember mth = memCache.methodHead();
            CtMember mthTail = memCache.lastMethod();
            while (mth != mthTail) {
                mth = mth.next();
                if (mth.getName().equals(name) && ((CtMethod) mth).getMethodInfo2().getDescriptor().equals(desc)) {
                    return (CtMethod) mth;
                }
            }
        }
        try {
            CtClass s = cc.getSuperclass();
            if (s != null) {
                CtMethod m = getMethod0(s, name, desc);
                if (m != null) {
                    return m;
                }
            }
        } catch (NotFoundException e) {
        }
        try {
            CtClass[] ifs = cc.getInterfaces();
            for (CtClass ctc : ifs) {
                CtMethod m2 = getMethod0(ctc, name, desc);
                if (m2 != null) {
                    return m2;
                }
            }
            return null;
        } catch (NotFoundException e2) {
            return null;
        }
    }

    @Override // javassist.CtClass
    public CtMethod[] getDeclaredMethods() {
        CtMember.Cache memCache = getMembers();
        CtMember mth = memCache.methodHead();
        CtMember mthTail = memCache.lastMethod();
        List<CtMember> methods = new ArrayList<>();
        while (mth != mthTail) {
            mth = mth.next();
            methods.add(mth);
        }
        return (CtMethod[]) methods.toArray(new CtMethod[methods.size()]);
    }

    @Override // javassist.CtClass
    public CtMethod[] getDeclaredMethods(String name) throws NotFoundException {
        CtMember.Cache memCache = getMembers();
        CtMember mth = memCache.methodHead();
        CtMember mthTail = memCache.lastMethod();
        List<CtMember> methods = new ArrayList<>();
        while (mth != mthTail) {
            mth = mth.next();
            if (mth.getName().equals(name)) {
                methods.add(mth);
            }
        }
        return (CtMethod[]) methods.toArray(new CtMethod[methods.size()]);
    }

    @Override // javassist.CtClass
    public CtMethod getDeclaredMethod(String name) throws NotFoundException {
        CtMember.Cache memCache = getMembers();
        CtMember mth = memCache.methodHead();
        CtMember mthTail = memCache.lastMethod();
        while (mth != mthTail) {
            mth = mth.next();
            if (mth.getName().equals(name)) {
                return (CtMethod) mth;
            }
        }
        throw new NotFoundException(name + "(..) is not found in " + getName());
    }

    @Override // javassist.CtClass
    public CtMethod getDeclaredMethod(String name, CtClass[] params) throws NotFoundException {
        String desc = Descriptor.ofParameters(params);
        CtMember.Cache memCache = getMembers();
        CtMember mth = memCache.methodHead();
        CtMember mthTail = memCache.lastMethod();
        while (mth != mthTail) {
            mth = mth.next();
            if (mth.getName().equals(name) && ((CtMethod) mth).getMethodInfo2().getDescriptor().startsWith(desc)) {
                return (CtMethod) mth;
            }
        }
        throw new NotFoundException(name + "(..) is not found in " + getName());
    }

    @Override // javassist.CtClass
    public void addField(CtField f, String init) throws CannotCompileException {
        addField(f, CtField.Initializer.byExpr(init));
    }

    @Override // javassist.CtClass
    public void addField(CtField f, CtField.Initializer init) throws CannotCompileException {
        checkModify();
        if (f.getDeclaringClass() != this) {
            throw new CannotCompileException("cannot add");
        }
        if (init == null) {
            init = f.getInit();
        }
        if (init != null) {
            init.check(f.getSignature());
            int mod = f.getModifiers();
            if (Modifier.isStatic(mod) && Modifier.isFinal(mod)) {
                try {
                    ConstPool cp = getClassFile2().getConstPool();
                    int index = init.getConstantValue(cp, f.getType());
                    if (index != 0) {
                        f.getFieldInfo2().addAttribute(new ConstantAttribute(cp, index));
                        init = null;
                    }
                } catch (NotFoundException e) {
                }
            }
        }
        getMembers().addField(f);
        getClassFile2().addField(f.getFieldInfo2());
        if (init != null) {
            FieldInitLink fil = new FieldInitLink(f, init);
            FieldInitLink link = this.fieldInitializers;
            if (link == null) {
                this.fieldInitializers = fil;
                return;
            }
            while (link.next != null) {
                link = link.next;
            }
            link.next = fil;
        }
    }

    @Override // javassist.CtClass
    public void removeField(CtField f) throws NotFoundException {
        checkModify();
        FieldInfo fi = f.getFieldInfo2();
        ClassFile cf = getClassFile2();
        if (cf.getFields().remove(fi)) {
            getMembers().remove(f);
            this.gcConstPool = true;
            return;
        }
        throw new NotFoundException(f.toString());
    }

    @Override // javassist.CtClass
    public CtConstructor makeClassInitializer() throws CannotCompileException {
        CtConstructor clinit = getClassInitializer();
        if (clinit != null) {
            return clinit;
        }
        checkModify();
        ClassFile cf = getClassFile2();
        Bytecode code = new Bytecode(cf.getConstPool(), 0, 0);
        modifyClassConstructor(cf, code, 0, 0);
        return getClassInitializer();
    }

    @Override // javassist.CtClass
    public void addConstructor(CtConstructor c) throws CannotCompileException {
        checkModify();
        if (c.getDeclaringClass() != this) {
            throw new CannotCompileException("cannot add");
        }
        getMembers().addConstructor(c);
        getClassFile2().addMethod(c.getMethodInfo2());
    }

    @Override // javassist.CtClass
    public void removeConstructor(CtConstructor m) throws NotFoundException {
        checkModify();
        MethodInfo mi = m.getMethodInfo2();
        ClassFile cf = getClassFile2();
        if (cf.getMethods().remove(mi)) {
            getMembers().remove(m);
            this.gcConstPool = true;
            return;
        }
        throw new NotFoundException(m.toString());
    }

    @Override // javassist.CtClass
    public void addMethod(CtMethod m) throws CannotCompileException {
        checkModify();
        if (m.getDeclaringClass() != this) {
            throw new CannotCompileException("bad declaring class");
        }
        int mod = m.getModifiers();
        if ((getModifiers() & 512) != 0) {
            if (Modifier.isProtected(mod) || Modifier.isPrivate(mod)) {
                throw new CannotCompileException("an interface method must be public: " + m.toString());
            }
            m.setModifiers(mod | 1);
        }
        getMembers().addMethod(m);
        getClassFile2().addMethod(m.getMethodInfo2());
        if ((mod & 1024) != 0) {
            setModifiers(getModifiers() | 1024);
        }
    }

    @Override // javassist.CtClass
    public void removeMethod(CtMethod m) throws NotFoundException {
        checkModify();
        MethodInfo mi = m.getMethodInfo2();
        ClassFile cf = getClassFile2();
        if (cf.getMethods().remove(mi)) {
            getMembers().remove(m);
            this.gcConstPool = true;
            return;
        }
        throw new NotFoundException(m.toString());
    }

    @Override // javassist.CtClass
    public byte[] getAttribute(String name) {
        AttributeInfo ai = getClassFile2().getAttribute(name);
        if (ai == null) {
            return null;
        }
        return ai.get();
    }

    @Override // javassist.CtClass
    public void setAttribute(String name, byte[] data) {
        checkModify();
        ClassFile cf = getClassFile2();
        cf.addAttribute(new AttributeInfo(cf.getConstPool(), name, data));
    }

    @Override // javassist.CtClass
    public void instrument(CodeConverter converter) throws CannotCompileException {
        MethodInfo[] methodInfoArr;
        checkModify();
        ClassFile cf = getClassFile2();
        ConstPool cp = cf.getConstPool();
        List<MethodInfo> methods = cf.getMethods();
        for (MethodInfo minfo : (MethodInfo[]) methods.toArray(new MethodInfo[methods.size()])) {
            converter.doit(this, minfo, cp);
        }
    }

    @Override // javassist.CtClass
    public void instrument(ExprEditor editor) throws CannotCompileException {
        MethodInfo[] methodInfoArr;
        checkModify();
        ClassFile cf = getClassFile2();
        List<MethodInfo> methods = cf.getMethods();
        for (MethodInfo minfo : (MethodInfo[]) methods.toArray(new MethodInfo[methods.size()])) {
            editor.doit(this, minfo);
        }
    }

    @Override // javassist.CtClass
    public void prune() {
        if (this.wasPruned) {
            return;
        }
        this.wasFrozen = true;
        this.wasPruned = true;
        getClassFile2().prune();
    }

    @Override // javassist.CtClass
    public void rebuildClassFile() {
        this.gcConstPool = true;
    }

    @Override // javassist.CtClass
    public void toBytecode(DataOutputStream out) throws CannotCompileException, IOException {
        try {
            if (isModified()) {
                checkPruned("toBytecode");
                ClassFile cf = getClassFile2();
                if (this.gcConstPool) {
                    cf.compact();
                    this.gcConstPool = false;
                }
                modifyClassConstructor(cf);
                modifyConstructors(cf);
                if (debugDump != null) {
                    dumpClassFile(cf);
                }
                cf.write(out);
                out.flush();
                this.fieldInitializers = null;
                if (this.doPruning) {
                    cf.prune();
                    this.wasPruned = true;
                }
            } else {
                this.classPool.writeClassfile(getName(), out);
            }
            this.getCount = 0;
            this.wasFrozen = true;
        } catch (IOException e) {
            throw new CannotCompileException(e);
        } catch (NotFoundException e2) {
            throw new CannotCompileException(e2);
        }
    }

    private void dumpClassFile(ClassFile cf) throws IOException {
        DataOutputStream dump = makeFileOutput(debugDump);
        try {
            cf.write(dump);
        } finally {
            dump.close();
        }
    }

    private void checkPruned(String method) {
        if (this.wasPruned) {
            throw new RuntimeException(method + "(): " + getName() + " was pruned.");
        }
    }

    @Override // javassist.CtClass
    public boolean stopPruning(boolean stop) {
        boolean prev = !this.doPruning;
        this.doPruning = !stop;
        return prev;
    }

    private void modifyClassConstructor(ClassFile cf) throws CannotCompileException, NotFoundException {
        if (this.fieldInitializers == null) {
            return;
        }
        Bytecode code = new Bytecode(cf.getConstPool(), 0, 0);
        Javac jv = new Javac(code, this);
        int stacksize = 0;
        boolean doInit = false;
        FieldInitLink fieldInitLink = this.fieldInitializers;
        while (true) {
            FieldInitLink fi = fieldInitLink;
            if (fi == null) {
                break;
            }
            CtField f = fi.field;
            if (Modifier.isStatic(f.getModifiers())) {
                doInit = true;
                int s = fi.init.compileIfStatic(f.getType(), f.getName(), code, jv);
                if (stacksize < s) {
                    stacksize = s;
                }
            }
            fieldInitLink = fi.next;
        }
        if (doInit) {
            modifyClassConstructor(cf, code, stacksize, 0);
        }
    }

    private void modifyClassConstructor(ClassFile cf, Bytecode code, int stacksize, int localsize) throws CannotCompileException {
        MethodInfo m = cf.getStaticInitializer();
        if (m == null) {
            code.add(Opcode.RETURN);
            code.setMaxStack(stacksize);
            code.setMaxLocals(localsize);
            m = new MethodInfo(cf.getConstPool(), MethodInfo.nameClinit, "()V");
            m.setAccessFlags(8);
            m.setCodeAttribute(code.toCodeAttribute());
            cf.addMethod(m);
            CtMember.Cache cache = hasMemberCache();
            if (cache != null) {
                cache.addConstructor(new CtConstructor(m, this));
            }
        } else {
            CodeAttribute codeAttr = m.getCodeAttribute();
            if (codeAttr == null) {
                throw new CannotCompileException("empty <clinit>");
            }
            try {
                CodeIterator it = codeAttr.iterator();
                int pos = it.insertEx(code.get());
                it.insert(code.getExceptionTable(), pos);
                int maxstack = codeAttr.getMaxStack();
                if (maxstack < stacksize) {
                    codeAttr.setMaxStack(stacksize);
                }
                int maxlocals = codeAttr.getMaxLocals();
                if (maxlocals < localsize) {
                    codeAttr.setMaxLocals(localsize);
                }
            } catch (BadBytecode e) {
                throw new CannotCompileException(e);
            }
        }
        try {
            m.rebuildStackMapIf6(this.classPool, cf);
        } catch (BadBytecode e2) {
            throw new CannotCompileException(e2);
        }
    }

    private void modifyConstructors(ClassFile cf) throws CannotCompileException, NotFoundException {
        CodeAttribute codeAttr;
        if (this.fieldInitializers == null) {
            return;
        }
        ConstPool cp = cf.getConstPool();
        List<MethodInfo> methods = cf.getMethods();
        for (MethodInfo minfo : methods) {
            if (minfo.isConstructor() && (codeAttr = minfo.getCodeAttribute()) != null) {
                try {
                    Bytecode init = new Bytecode(cp, 0, codeAttr.getMaxLocals());
                    CtClass[] params = Descriptor.getParameterTypes(minfo.getDescriptor(), this.classPool);
                    int stacksize = makeFieldInitializer(init, params);
                    insertAuxInitializer(codeAttr, init, stacksize);
                    minfo.rebuildStackMapIf6(this.classPool, cf);
                } catch (BadBytecode e) {
                    throw new CannotCompileException(e);
                }
            }
        }
    }

    private static void insertAuxInitializer(CodeAttribute codeAttr, Bytecode initializer, int stacksize) throws BadBytecode {
        CodeIterator it = codeAttr.iterator();
        int index = it.skipSuperConstructor();
        if (index < 0) {
            int index2 = it.skipThisConstructor();
            if (index2 >= 0) {
                return;
            }
        }
        int pos = it.insertEx(initializer.get());
        it.insert(initializer.getExceptionTable(), pos);
        int maxstack = codeAttr.getMaxStack();
        if (maxstack < stacksize) {
            codeAttr.setMaxStack(stacksize);
        }
    }

    private int makeFieldInitializer(Bytecode code, CtClass[] parameters) throws CannotCompileException, NotFoundException {
        int s;
        int stacksize = 0;
        Javac jv = new Javac(code, this);
        try {
            jv.recordParams(parameters, false);
            FieldInitLink fieldInitLink = this.fieldInitializers;
            while (true) {
                FieldInitLink fi = fieldInitLink;
                if (fi != null) {
                    CtField f = fi.field;
                    if (!Modifier.isStatic(f.getModifiers()) && stacksize < (s = fi.init.compile(f.getType(), f.getName(), code, parameters, jv))) {
                        stacksize = s;
                    }
                    fieldInitLink = fi.next;
                } else {
                    return stacksize;
                }
            }
        } catch (CompileError e) {
            throw new CannotCompileException(e);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Map<CtMethod, String> getHiddenMethods() {
        if (this.hiddenMethods == null) {
            this.hiddenMethods = new Hashtable();
        }
        return this.hiddenMethods;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getUniqueNumber() {
        int i = this.uniqueNumberSeed;
        this.uniqueNumberSeed = i + 1;
        return i;
    }

    @Override // javassist.CtClass
    public String makeUniqueName(String prefix) {
        Map<Object, CtClassType> table = new HashMap<>();
        makeMemberList(table);
        Set<Object> keys = table.keySet();
        String[] methods = new String[keys.size()];
        keys.toArray(methods);
        if (notFindInArray(prefix, methods)) {
            return prefix;
        }
        int i = 100;
        while (i <= 999) {
            int i2 = i;
            i++;
            String name = prefix + i2;
            if (notFindInArray(name, methods)) {
                return name;
            }
        }
        throw new RuntimeException("too many unique name");
    }

    private static boolean notFindInArray(String prefix, String[] values) {
        for (String str : values) {
            if (str.startsWith(prefix)) {
                return false;
            }
        }
        return true;
    }

    private void makeMemberList(Map<Object, CtClassType> table) {
        int mod = getModifiers();
        if (Modifier.isAbstract(mod) || Modifier.isInterface(mod)) {
            try {
                CtClass[] ifs = getInterfaces();
                for (CtClass ic : ifs) {
                    if (ic != null && (ic instanceof CtClassType)) {
                        ((CtClassType) ic).makeMemberList(table);
                    }
                }
            } catch (NotFoundException e) {
            }
        }
        try {
            CtClass s = getSuperclass();
            if (s != null && (s instanceof CtClassType)) {
                ((CtClassType) s).makeMemberList(table);
            }
        } catch (NotFoundException e2) {
        }
        List<MethodInfo> methods = getClassFile2().getMethods();
        for (MethodInfo minfo : methods) {
            table.put(minfo.getName(), this);
        }
        List<FieldInfo> fields = getClassFile2().getFields();
        for (FieldInfo finfo : fields) {
            table.put(finfo.getName(), this);
        }
    }
}