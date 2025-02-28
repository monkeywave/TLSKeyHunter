package javassist;

import javassist.CtMethod;
import javassist.bytecode.Bytecode;
import javassist.bytecode.ConstPool;
import javassist.bytecode.ExceptionsAttribute;
import javassist.bytecode.FieldInfo;
import javassist.bytecode.MethodInfo;
import javassist.compiler.CompileError;
import javassist.compiler.Javac;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/CtNewMethod.class */
public class CtNewMethod {
    public static CtMethod make(String src, CtClass declaring) throws CannotCompileException {
        return make(src, declaring, null, null);
    }

    public static CtMethod make(String src, CtClass declaring, String delegateObj, String delegateMethod) throws CannotCompileException {
        Javac compiler = new Javac(declaring);
        if (delegateMethod != null) {
            try {
                compiler.recordProceed(delegateObj, delegateMethod);
            } catch (CompileError e) {
                throw new CannotCompileException(e);
            }
        }
        CtMember obj = compiler.compile(src);
        if (obj instanceof CtMethod) {
            return (CtMethod) obj;
        }
        throw new CannotCompileException("not a method");
    }

    public static CtMethod make(CtClass returnType, String mname, CtClass[] parameters, CtClass[] exceptions, String body, CtClass declaring) throws CannotCompileException {
        return make(1, returnType, mname, parameters, exceptions, body, declaring);
    }

    public static CtMethod make(int modifiers, CtClass returnType, String mname, CtClass[] parameters, CtClass[] exceptions, String body, CtClass declaring) throws CannotCompileException {
        try {
            CtMethod cm = new CtMethod(returnType, mname, parameters, declaring);
            cm.setModifiers(modifiers);
            cm.setExceptionTypes(exceptions);
            cm.setBody(body);
            return cm;
        } catch (NotFoundException e) {
            throw new CannotCompileException(e);
        }
    }

    public static CtMethod copy(CtMethod src, CtClass declaring, ClassMap map) throws CannotCompileException {
        return new CtMethod(src, declaring, map);
    }

    public static CtMethod copy(CtMethod src, String name, CtClass declaring, ClassMap map) throws CannotCompileException {
        CtMethod cm = new CtMethod(src, declaring, map);
        cm.setName(name);
        return cm;
    }

    public static CtMethod abstractMethod(CtClass returnType, String mname, CtClass[] parameters, CtClass[] exceptions, CtClass declaring) throws NotFoundException {
        CtMethod cm = new CtMethod(returnType, mname, parameters, declaring);
        cm.setExceptionTypes(exceptions);
        return cm;
    }

    public static CtMethod getter(String methodName, CtField field) throws CannotCompileException {
        FieldInfo finfo = field.getFieldInfo2();
        String fieldType = finfo.getDescriptor();
        String desc = "()" + fieldType;
        ConstPool cp = finfo.getConstPool();
        MethodInfo minfo = new MethodInfo(cp, methodName, desc);
        minfo.setAccessFlags(1);
        Bytecode code = new Bytecode(cp, 2, 1);
        try {
            String fieldName = finfo.getName();
            if ((finfo.getAccessFlags() & 8) == 0) {
                code.addAload(0);
                code.addGetfield(Bytecode.THIS, fieldName, fieldType);
            } else {
                code.addGetstatic(Bytecode.THIS, fieldName, fieldType);
            }
            code.addReturn(field.getType());
            minfo.setCodeAttribute(code.toCodeAttribute());
            CtClass cc = field.getDeclaringClass();
            return new CtMethod(minfo, cc);
        } catch (NotFoundException e) {
            throw new CannotCompileException(e);
        }
    }

    public static CtMethod setter(String methodName, CtField field) throws CannotCompileException {
        FieldInfo finfo = field.getFieldInfo2();
        String fieldType = finfo.getDescriptor();
        String desc = "(" + fieldType + ")V";
        ConstPool cp = finfo.getConstPool();
        MethodInfo minfo = new MethodInfo(cp, methodName, desc);
        minfo.setAccessFlags(1);
        Bytecode code = new Bytecode(cp, 3, 3);
        try {
            String fieldName = finfo.getName();
            if ((finfo.getAccessFlags() & 8) == 0) {
                code.addAload(0);
                code.addLoad(1, field.getType());
                code.addPutfield(Bytecode.THIS, fieldName, fieldType);
            } else {
                code.addLoad(1, field.getType());
                code.addPutstatic(Bytecode.THIS, fieldName, fieldType);
            }
            code.addReturn(null);
            minfo.setCodeAttribute(code.toCodeAttribute());
            CtClass cc = field.getDeclaringClass();
            return new CtMethod(minfo, cc);
        } catch (NotFoundException e) {
            throw new CannotCompileException(e);
        }
    }

    public static CtMethod delegator(CtMethod delegate, CtClass declaring) throws CannotCompileException {
        try {
            return delegator0(delegate, declaring);
        } catch (NotFoundException e) {
            throw new CannotCompileException(e);
        }
    }

    private static CtMethod delegator0(CtMethod delegate, CtClass declaring) throws CannotCompileException, NotFoundException {
        int s;
        MethodInfo deleInfo = delegate.getMethodInfo2();
        String methodName = deleInfo.getName();
        String desc = deleInfo.getDescriptor();
        ConstPool cp = declaring.getClassFile2().getConstPool();
        MethodInfo minfo = new MethodInfo(cp, methodName, desc);
        minfo.setAccessFlags(deleInfo.getAccessFlags());
        ExceptionsAttribute eattr = deleInfo.getExceptionsAttribute();
        if (eattr != null) {
            minfo.setExceptionsAttribute((ExceptionsAttribute) eattr.copy(cp, null));
        }
        Bytecode code = new Bytecode(cp, 0, 0);
        boolean isStatic = Modifier.isStatic(delegate.getModifiers());
        CtClass deleClass = delegate.getDeclaringClass();
        CtClass[] params = delegate.getParameterTypes();
        if (isStatic) {
            s = code.addLoadParameters(params, 0);
            code.addInvokestatic(deleClass, methodName, desc);
        } else {
            code.addLoad(0, deleClass);
            s = code.addLoadParameters(params, 1);
            code.addInvokespecial(deleClass, methodName, desc);
        }
        code.addReturn(delegate.getReturnType());
        int s2 = s + 1;
        code.setMaxLocals(s2);
        code.setMaxStack(s2 < 2 ? 2 : s2);
        minfo.setCodeAttribute(code.toCodeAttribute());
        return new CtMethod(minfo, declaring);
    }

    public static CtMethod wrapped(CtClass returnType, String mname, CtClass[] parameterTypes, CtClass[] exceptionTypes, CtMethod body, CtMethod.ConstParameter constParam, CtClass declaring) throws CannotCompileException {
        return CtNewWrappedMethod.wrapped(returnType, mname, parameterTypes, exceptionTypes, body, constParam, declaring);
    }
}