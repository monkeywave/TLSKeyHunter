package org.openjsse.sun.security.ssl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import javassist.compiler.TokenId;
import org.openjsse.sun.security.util.HexDumpEncoder;
import sun.security.action.GetPropertyAction;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLLogger.class */
public final class SSLLogger {
    private static final SSLConsoleLogger logger;
    private static final String property;
    public static final boolean isOn;

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLLogger$Level.class */
    public enum Level {
        ALL(Integer.MIN_VALUE),
        TRACE(TokenId.Identifier),
        DEBUG(TokenId.BadToken),
        INFO(800),
        WARNING(900),
        ERROR(1000),
        OFF(Integer.MAX_VALUE);
        
        private final int severity;

        Level(int severity) {
            this.severity = severity;
        }

        public final String getName() {
            return name();
        }

        public final int getSeverity() {
            return this.severity;
        }
    }

    static {
        String p = GetPropertyAction.privilegedGetProperty("javax.net.debug");
        if (p != null) {
            if (p.isEmpty()) {
                property = "";
                logger = new SSLConsoleLogger("javax.net.ssl", p);
            } else {
                property = p.toLowerCase(Locale.ENGLISH);
                if (property.equals("help")) {
                    help();
                }
                logger = new SSLConsoleLogger("javax.net.ssl", p);
            }
            isOn = true;
            return;
        }
        property = null;
        logger = null;
        isOn = false;
    }

    private static void help() {
        System.err.println();
        System.err.println("help           print the help messages");
        System.err.println("expand         expand debugging information");
        System.err.println();
        System.err.println("all            turn on all debugging");
        System.err.println("ssl            turn on ssl debugging");
        System.err.println();
        System.err.println("The following can be used with ssl:");
        System.err.println("\trecord       enable per-record tracing");
        System.err.println("\thandshake    print each handshake message");
        System.err.println("\tkeygen       print key generation data");
        System.err.println("\tsession      print session activity");
        System.err.println("\tdefaultctx   print default SSL initialization");
        System.err.println("\tsslctx       print SSLContext tracing");
        System.err.println("\tsessioncache print session cache tracing");
        System.err.println("\tkeymanager   print key manager tracing");
        System.err.println("\ttrustmanager print trust manager tracing");
        System.err.println("\tpluggability print pluggability tracing");
        System.err.println();
        System.err.println("\thandshake debugging can be widened with:");
        System.err.println("\tdata         hex dump of each handshake message");
        System.err.println("\tverbose      verbose handshake message printing");
        System.err.println();
        System.err.println("\trecord debugging can be widened with:");
        System.err.println("\tplaintext    hex dump of record plaintext");
        System.err.println("\tpacket       print raw SSL/TLS packets");
        System.err.println();
        System.exit(0);
    }

    public static boolean isOn(String checkPoints) {
        if (property == null) {
            return false;
        }
        if (property.isEmpty()) {
            return true;
        }
        String[] options = checkPoints.split(",");
        for (String option : options) {
            if (!hasOption(option.trim())) {
                return false;
            }
        }
        return true;
    }

    private static boolean hasOption(String option) {
        String option2 = option.toLowerCase(Locale.ENGLISH);
        if (property.contains("all")) {
            return true;
        }
        int offset = property.indexOf("ssl");
        if (offset != -1 && property.indexOf("sslctx", offset) != -1 && !option2.equals("data") && !option2.equals("packet") && !option2.equals("plaintext")) {
            return true;
        }
        return property.contains(option2);
    }

    public static void severe(String msg, Object... params) {
        log(Level.ERROR, msg, params);
    }

    public static void warning(String msg, Object... params) {
        log(Level.WARNING, msg, params);
    }

    public static void info(String msg, Object... params) {
        log(Level.INFO, msg, params);
    }

    public static void fine(String msg, Object... params) {
        log(Level.DEBUG, msg, params);
    }

    public static void finer(String msg, Object... params) {
        log(Level.TRACE, msg, params);
    }

    public static void finest(String msg, Object... params) {
        log(Level.ALL, msg, params);
    }

    private static void log(Level level, String msg, Object... params) {
        if (logger.isLoggable(level)) {
            if (params == null || params.length == 0) {
                logger.log(level, msg, new Object[0]);
                return;
            }
            try {
                String formatted = SSLSimpleFormatter.formatParameters(params);
                logger.log(level, msg, formatted);
            } catch (Exception e) {
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String toString(Object... params) {
        try {
            return SSLSimpleFormatter.formatParameters(params);
        } catch (Exception exp) {
            return "unexpected exception thrown: " + exp.getMessage();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLLogger$SSLConsoleLogger.class */
    public static class SSLConsoleLogger {
        private final String loggerName;
        private final boolean useCompactFormat;

        SSLConsoleLogger(String loggerName, String options) {
            this.loggerName = loggerName;
            this.useCompactFormat = !options.toLowerCase(Locale.ENGLISH).contains("expand");
        }

        public String getName() {
            return this.loggerName;
        }

        public boolean isLoggable(Level level) {
            return level != Level.OFF;
        }

        public void log(Level level, String message, Object... params) {
            if (!isLoggable(level)) {
                return;
            }
            try {
                String formatted = SSLSimpleFormatter.format(this, level, message, params);
                System.err.write(formatted.getBytes("UTF-8"));
            } catch (Exception e) {
            }
        }

        public void log(Level level, ResourceBundle rb, String message, Throwable thrwbl) {
            if (!isLoggable(level)) {
                return;
            }
            try {
                String formatted = SSLSimpleFormatter.format(this, level, message, thrwbl);
                System.err.write(formatted.getBytes("UTF-8"));
            } catch (Exception e) {
            }
        }

        public void log(Level level, ResourceBundle rb, String message, Object... params) {
            if (!isLoggable(level)) {
                return;
            }
            try {
                String formatted = SSLSimpleFormatter.format(this, level, message, params);
                System.err.write(formatted.getBytes("UTF-8"));
            } catch (Exception e) {
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLLogger$SSLSimpleFormatter.class */
    public static class SSLSimpleFormatter {
        private static final ThreadLocal<SimpleDateFormat> dateFormat = new ThreadLocal<SimpleDateFormat>() { // from class: org.openjsse.sun.security.ssl.SSLLogger.SSLSimpleFormatter.1
            /* JADX INFO: Access modifiers changed from: protected */
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // java.lang.ThreadLocal
            public SimpleDateFormat initialValue() {
                return new SimpleDateFormat("yyyy-MM-dd kk:mm:ss.SSS z", Locale.ENGLISH);
            }
        };
        private static final MessageFormat basicCertFormat = new MessageFormat("\"version\"            : \"v{0}\",\n\"serial number\"      : \"{1}\",\n\"signature algorithm\": \"{2}\",\n\"issuer\"             : \"{3}\",\n\"not before\"         : \"{4}\",\n\"not  after\"         : \"{5}\",\n\"subject\"            : \"{6}\",\n\"subject public key\" : \"{7}\"\n", Locale.ENGLISH);
        private static final MessageFormat extendedCertFormart = new MessageFormat("\"version\"            : \"v{0}\",\n\"serial number\"      : \"{1}\",\n\"signature algorithm\": \"{2}\",\n\"issuer\"             : \"{3}\",\n\"not before\"         : \"{4}\",\n\"not  after\"         : \"{5}\",\n\"subject\"            : \"{6}\",\n\"subject public key\" : \"{7}\",\n\"extensions\"         : [\n{8}\n]\n", Locale.ENGLISH);
        private static final MessageFormat messageFormatNoParas = new MessageFormat("'{'\n  \"logger\"      : \"{0}\",\n  \"level\"       : \"{1}\",\n  \"thread id\"   : \"{2}\",\n  \"thread name\" : \"{3}\",\n  \"time\"        : \"{4}\",\n  \"caller\"      : \"{5}\",\n  \"message\"     : \"{6}\"\n'}'\n", Locale.ENGLISH);
        private static final MessageFormat messageCompactFormatNoParas = new MessageFormat("{0}|{1}|{2}|{3}|{4}|{5}|{6}\n", Locale.ENGLISH);
        private static final MessageFormat messageFormatWithParas = new MessageFormat("'{'\n  \"logger\"      : \"{0}\",\n  \"level\"       : \"{1}\",\n  \"thread id\"   : \"{2}\",\n  \"thread name\" : \"{3}\",\n  \"time\"        : \"{4}\",\n  \"caller\"      : \"{5}\",\n  \"message\"     : \"{6}\",\n  \"specifics\"   : [\n{7}\n  ]\n'}'\n", Locale.ENGLISH);
        private static final MessageFormat messageCompactFormatWithParas = new MessageFormat("{0}|{1}|{2}|{3}|{4}|{5}|{6} (\n{7}\n)\n", Locale.ENGLISH);
        private static final MessageFormat keyObjectFormat = new MessageFormat("\"{0}\" : '{'\n{1}'}'\n", Locale.ENGLISH);

        private SSLSimpleFormatter() {
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static String format(SSLConsoleLogger logger, Level level, String message, Object... parameters) {
            String indent;
            if (parameters == null || parameters.length == 0) {
                Object[] messageFields = {logger.loggerName, level.getName(), Utilities.toHexString(Thread.currentThread().getId()), Thread.currentThread().getName(), dateFormat.get().format(new Date(System.currentTimeMillis())), formatCaller(), message};
                if (logger.useCompactFormat) {
                    return messageCompactFormatNoParas.format(messageFields);
                }
                return messageFormatNoParas.format(messageFields);
            }
            Object[] messageFields2 = new Object[8];
            messageFields2[0] = logger.loggerName;
            messageFields2[1] = level.getName();
            messageFields2[2] = Utilities.toHexString(Thread.currentThread().getId());
            messageFields2[3] = Thread.currentThread().getName();
            messageFields2[4] = dateFormat.get().format(new Date(System.currentTimeMillis()));
            messageFields2[5] = formatCaller();
            messageFields2[6] = message;
            if (logger.useCompactFormat) {
                indent = formatParameters(parameters);
            } else {
                indent = Utilities.indent(formatParameters(parameters));
            }
            messageFields2[7] = indent;
            if (logger.useCompactFormat) {
                return messageCompactFormatWithParas.format(messageFields2);
            }
            return messageFormatWithParas.format(messageFields2);
        }

        private static String formatCaller() {
            StackTraceElement[] stElements = Thread.currentThread().getStackTrace();
            for (int i = 1; i < stElements.length; i++) {
                StackTraceElement ste = stElements[i];
                if (!ste.getClassName().startsWith(SSLLogger.class.getName()) && !ste.getClassName().startsWith("java.lang.System")) {
                    return ste.getFileName() + ":" + ste.getLineNumber();
                }
            }
            return "unknown caller";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static String formatParameters(Object... parameters) {
            StringBuilder builder = new StringBuilder(512);
            boolean isFirst = true;
            for (Object parameter : parameters) {
                if (isFirst) {
                    isFirst = false;
                } else {
                    builder.append(",\n");
                }
                if (parameter instanceof Throwable) {
                    builder.append(formatThrowable((Throwable) parameter));
                } else if (parameter instanceof Certificate) {
                    builder.append(formatCertificate((Certificate) parameter));
                } else if (parameter instanceof ByteArrayInputStream) {
                    builder.append(formatByteArrayInputStream((ByteArrayInputStream) parameter));
                } else if (parameter instanceof ByteBuffer) {
                    builder.append(formatByteBuffer((ByteBuffer) parameter));
                } else if (parameter instanceof byte[]) {
                    builder.append(formatByteArrayInputStream(new ByteArrayInputStream((byte[]) parameter)));
                } else if (parameter instanceof Map.Entry) {
                    Map.Entry<String, ?> mapParameter = (Map.Entry) parameter;
                    builder.append(formatMapEntry(mapParameter));
                } else {
                    builder.append(formatObject(parameter));
                }
            }
            return builder.toString();
        }

        private static String formatThrowable(Throwable throwable) {
            StringBuilder builder = new StringBuilder(512);
            ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
            PrintStream out = new PrintStream(bytesOut);
            Throwable th = null;
            try {
                throwable.printStackTrace(out);
                builder.append(Utilities.indent(bytesOut.toString()));
                if (out != null) {
                    if (0 != 0) {
                        try {
                            out.close();
                        } catch (Throwable th2) {
                            th.addSuppressed(th2);
                        }
                    } else {
                        out.close();
                    }
                }
                Object[] fields = {"throwable", builder.toString()};
                return keyObjectFormat.format(fields);
            } finally {
            }
        }

        private static String formatCertificate(Certificate certificate) {
            if (!(certificate instanceof X509Certificate)) {
                return Utilities.indent(certificate.toString());
            }
            StringBuilder builder = new StringBuilder(512);
            try {
                X509CertImpl x509 = X509CertImpl.toImpl((X509Certificate) certificate);
                X509CertInfo certInfo = (X509CertInfo) x509.get("x509.info");
                CertificateExtensions certExts = (CertificateExtensions) certInfo.get("extensions");
                if (certExts == null) {
                    Object[] certFields = {Integer.valueOf(x509.getVersion()), Utilities.toHexString(x509.getSerialNumber().toByteArray()), x509.getSigAlgName(), x509.getIssuerX500Principal().toString(), dateFormat.get().format(x509.getNotBefore()), dateFormat.get().format(x509.getNotAfter()), x509.getSubjectX500Principal().toString(), x509.getPublicKey().getAlgorithm()};
                    builder.append(Utilities.indent(basicCertFormat.format(certFields)));
                } else {
                    StringBuilder extBuilder = new StringBuilder(512);
                    boolean isFirst = true;
                    for (Extension certExt : certExts.getAllExtensions()) {
                        if (isFirst) {
                            isFirst = false;
                        } else {
                            extBuilder.append(",\n");
                        }
                        extBuilder.append("{\n" + Utilities.indent(certExt.toString()) + "\n}");
                    }
                    Object[] certFields2 = {Integer.valueOf(x509.getVersion()), Utilities.toHexString(x509.getSerialNumber().toByteArray()), x509.getSigAlgName(), x509.getIssuerX500Principal().toString(), dateFormat.get().format(x509.getNotBefore()), dateFormat.get().format(x509.getNotAfter()), x509.getSubjectX500Principal().toString(), x509.getPublicKey().getAlgorithm(), Utilities.indent(extBuilder.toString())};
                    builder.append(Utilities.indent(extendedCertFormart.format(certFields2)));
                }
            } catch (Exception e) {
            }
            Object[] fields = {"certificate", builder.toString()};
            return Utilities.indent(keyObjectFormat.format(fields));
        }

        private static String formatByteArrayInputStream(ByteArrayInputStream bytes) {
            StringBuilder builder = new StringBuilder(512);
            try {
                ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
                HexDumpEncoder hexEncoder = new HexDumpEncoder();
                hexEncoder.encodeBuffer(bytes, bytesOut);
                builder.append(Utilities.indent(bytesOut.toString()));
                if (bytesOut != null) {
                    if (0 != 0) {
                        bytesOut.close();
                    } else {
                        bytesOut.close();
                    }
                }
            } catch (IOException e) {
            }
            return builder.toString();
        }

        private static String formatByteBuffer(ByteBuffer byteBuffer) {
            StringBuilder builder = new StringBuilder(512);
            try {
                ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
                HexDumpEncoder hexEncoder = new HexDumpEncoder();
                hexEncoder.encodeBuffer(byteBuffer.duplicate(), bytesOut);
                builder.append(Utilities.indent(bytesOut.toString()));
                if (bytesOut != null) {
                    if (0 != 0) {
                        bytesOut.close();
                    } else {
                        bytesOut.close();
                    }
                }
            } catch (IOException e) {
            }
            return builder.toString();
        }

        private static String formatMapEntry(Map.Entry<String, ?> entry) {
            String formatted;
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof String) {
                formatted = "\"" + key + "\": \"" + ((String) value) + "\"";
            } else if (value instanceof String[]) {
                StringBuilder builder = new StringBuilder(512);
                String[] strings = (String[]) value;
                builder.append("\"" + key + "\": [\n");
                for (String string : strings) {
                    builder.append("      \"" + string + "\"");
                    if (string != strings[strings.length - 1]) {
                        builder.append(",");
                    }
                    builder.append("\n");
                }
                builder.append("      ]");
                formatted = builder.toString();
            } else if (value instanceof byte[]) {
                formatted = "\"" + key + "\": \"" + Utilities.toHexString((byte[]) value) + "\"";
            } else if (value instanceof Byte) {
                formatted = "\"" + key + "\": \"" + Utilities.toHexString(((Byte) value).byteValue()) + "\"";
            } else {
                formatted = "\"" + key + "\": \"" + value.toString() + "\"";
            }
            return Utilities.indent(formatted);
        }

        private static String formatObject(Object obj) {
            return obj.toString();
        }
    }
}