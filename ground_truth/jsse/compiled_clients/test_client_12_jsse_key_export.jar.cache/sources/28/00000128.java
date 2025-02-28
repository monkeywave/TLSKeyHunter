package javassist.compiler;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/compiler/SyntaxError.class */
public class SyntaxError extends CompileError {
    private static final long serialVersionUID = 1;

    public SyntaxError(Lex lexer) {
        super("syntax error near \"" + lexer.getTextAround() + "\"", lexer);
    }
}