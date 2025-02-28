package javassist.compiler;

import javassist.bytecode.Bytecode;
import javassist.compiler.ast.ASTList;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/compiler/ProceedHandler.class */
public interface ProceedHandler {
    void doit(JvstCodeGen jvstCodeGen, Bytecode bytecode, ASTList aSTList) throws CompileError;

    void setReturnType(JvstTypeChecker jvstTypeChecker, ASTList aSTList) throws CompileError;
}