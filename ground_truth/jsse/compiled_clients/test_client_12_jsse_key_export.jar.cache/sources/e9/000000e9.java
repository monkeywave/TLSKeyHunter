package javassist.bytecode.annotation;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;
import javassist.bytecode.AnnotationDefaultAttribute;
import javassist.bytecode.ClassFile;
import javassist.bytecode.MethodInfo;
import javassist.bytecode.Opcode;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/annotation/AnnotationImpl.class */
public class AnnotationImpl implements InvocationHandler {
    private static final String JDK_ANNOTATION_CLASS_NAME = "java.lang.annotation.Annotation";
    private static Method JDK_ANNOTATION_TYPE_METHOD;
    private Annotation annotation;
    private ClassPool pool;
    private ClassLoader classLoader;
    private transient Class<?> annotationType;
    private transient int cachedHashCode = Integer.MIN_VALUE;

    static {
        JDK_ANNOTATION_TYPE_METHOD = null;
        try {
            Class<?> clazz = Class.forName(JDK_ANNOTATION_CLASS_NAME);
            JDK_ANNOTATION_TYPE_METHOD = clazz.getMethod("annotationType", null);
        } catch (Exception e) {
        }
    }

    public static Object make(ClassLoader cl, Class<?> clazz, ClassPool cp, Annotation anon) throws IllegalArgumentException {
        AnnotationImpl handler = new AnnotationImpl(anon, cp, cl);
        return Proxy.newProxyInstance(cl, new Class[]{clazz}, handler);
    }

    private AnnotationImpl(Annotation a, ClassPool cp, ClassLoader loader) {
        this.annotation = a;
        this.pool = cp;
        this.classLoader = loader;
    }

    public String getTypeName() {
        return this.annotation.getTypeName();
    }

    private Class<?> getAnnotationType() {
        if (this.annotationType == null) {
            String typeName = this.annotation.getTypeName();
            try {
                this.annotationType = this.classLoader.loadClass(typeName);
            } catch (ClassNotFoundException e) {
                NoClassDefFoundError error = new NoClassDefFoundError("Error loading annotation class: " + typeName);
                error.setStackTrace(e.getStackTrace());
                throw error;
            }
        }
        return this.annotationType;
    }

    public Annotation getAnnotation() {
        return this.annotation;
    }

    @Override // java.lang.reflect.InvocationHandler
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        String name = method.getName();
        if (Object.class == method.getDeclaringClass()) {
            if ("equals".equals(name)) {
                Object obj = args[0];
                return Boolean.valueOf(checkEquals(obj));
            } else if ("toString".equals(name)) {
                return this.annotation.toString();
            } else {
                if ("hashCode".equals(name)) {
                    return Integer.valueOf(hashCode());
                }
            }
        } else if ("annotationType".equals(name) && method.getParameterTypes().length == 0) {
            return getAnnotationType();
        }
        MemberValue mv = this.annotation.getMemberValue(name);
        if (mv == null) {
            return getDefault(name, method);
        }
        return mv.getValue(this.classLoader, this.pool, method);
    }

    private Object getDefault(String name, Method method) throws ClassNotFoundException, RuntimeException {
        AnnotationDefaultAttribute ainfo;
        String classname = this.annotation.getTypeName();
        if (this.pool != null) {
            try {
                CtClass cc = this.pool.get(classname);
                ClassFile cf = cc.getClassFile2();
                MethodInfo minfo = cf.getMethod(name);
                if (minfo != null && (ainfo = (AnnotationDefaultAttribute) minfo.getAttribute(AnnotationDefaultAttribute.tag)) != null) {
                    MemberValue mv = ainfo.getDefaultValue();
                    return mv.getValue(this.classLoader, this.pool, method);
                }
            } catch (NotFoundException e) {
                throw new RuntimeException("cannot find a class file: " + classname);
            }
        }
        throw new RuntimeException("no default value: " + classname + "." + name + "()");
    }

    public int hashCode() {
        if (this.cachedHashCode == Integer.MIN_VALUE) {
            int hashCode = 0;
            getAnnotationType();
            Method[] methods = this.annotationType.getDeclaredMethods();
            for (int i = 0; i < methods.length; i++) {
                String name = methods[i].getName();
                int valueHashCode = 0;
                MemberValue mv = this.annotation.getMemberValue(name);
                Object value = null;
                if (mv != null) {
                    try {
                        value = mv.getValue(this.classLoader, this.pool, methods[i]);
                    } catch (RuntimeException e) {
                        throw e;
                    } catch (Exception e2) {
                        throw new RuntimeException("Error retrieving value " + name + " for annotation " + this.annotation.getTypeName(), e2);
                    }
                }
                if (value == null) {
                    value = getDefault(name, methods[i]);
                }
                if (value != null) {
                    if (value.getClass().isArray()) {
                        valueHashCode = arrayHashCode(value);
                    } else {
                        valueHashCode = value.hashCode();
                    }
                }
                hashCode += (Opcode.LAND * name.hashCode()) ^ valueHashCode;
            }
            this.cachedHashCode = hashCode;
        }
        return this.cachedHashCode;
    }

    private boolean checkEquals(Object obj) throws Exception {
        if (obj == null) {
            return false;
        }
        if (obj instanceof Proxy) {
            InvocationHandler ih = Proxy.getInvocationHandler(obj);
            if (ih instanceof AnnotationImpl) {
                AnnotationImpl other = (AnnotationImpl) ih;
                return this.annotation.equals(other.annotation);
            }
        }
        Class<?> otherAnnotationType = (Class) JDK_ANNOTATION_TYPE_METHOD.invoke(obj, new Object[0]);
        if (!getAnnotationType().equals(otherAnnotationType)) {
            return false;
        }
        Method[] methods = this.annotationType.getDeclaredMethods();
        for (int i = 0; i < methods.length; i++) {
            String name = methods[i].getName();
            MemberValue mv = this.annotation.getMemberValue(name);
            Object value = null;
            if (mv != null) {
                try {
                    value = mv.getValue(this.classLoader, this.pool, methods[i]);
                } catch (RuntimeException e) {
                    throw e;
                } catch (Exception e2) {
                    throw new RuntimeException("Error retrieving value " + name + " for annotation " + this.annotation.getTypeName(), e2);
                }
            }
            if (value == null) {
                value = getDefault(name, methods[i]);
            }
            Object otherValue = methods[i].invoke(obj, new Object[0]);
            if (value == null && otherValue != null) {
                return false;
            }
            if (value != null && !value.equals(otherValue)) {
                return false;
            }
        }
        return true;
    }

    private static int arrayHashCode(Object object) {
        if (object == null) {
            return 0;
        }
        int result = 1;
        Object[] array = (Object[]) object;
        for (int i = 0; i < array.length; i++) {
            int elementHashCode = 0;
            if (array[i] != null) {
                elementHashCode = array[i].hashCode();
            }
            result = (31 * result) + elementHashCode;
        }
        return result;
    }
}