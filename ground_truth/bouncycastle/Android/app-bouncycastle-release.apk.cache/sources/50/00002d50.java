package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public class HandshakeType {
    public static final short certificate = 11;
    public static final short certificate_request = 13;
    public static final short certificate_status = 22;
    public static final short certificate_url = 21;
    public static final short certificate_verify = 15;
    public static final short client_hello = 1;
    public static final short client_key_exchange = 16;
    public static final short compressed_certificate = 25;
    public static final short encrypted_extensions = 8;
    public static final short end_of_early_data = 5;
    public static final short finished = 20;
    public static final short hello_request = 0;
    public static final short hello_retry_request = 6;
    public static final short hello_verify_request = 3;
    public static final short key_update = 24;
    public static final short message_hash = 254;
    public static final short new_session_ticket = 4;
    public static final short server_hello = 2;
    public static final short server_hello_done = 14;
    public static final short server_key_exchange = 12;
    public static final short supplemental_data = 23;

    public static String getName(short s) {
        if (s != 8) {
            if (s != 254) {
                switch (s) {
                    case 0:
                        return "hello_request";
                    case 1:
                        return "client_hello";
                    case 2:
                        return "server_hello";
                    case 3:
                        return "hello_verify_request";
                    case 4:
                        return "new_session_ticket";
                    case 5:
                        return "end_of_early_data";
                    case 6:
                        return "hello_retry_request";
                    default:
                        switch (s) {
                            case 11:
                                return "certificate";
                            case 12:
                                return "server_key_exchange";
                            case 13:
                                return "certificate_request";
                            case 14:
                                return "server_hello_done";
                            case 15:
                                return "certificate_verify";
                            case 16:
                                return "client_key_exchange";
                            default:
                                switch (s) {
                                    case 20:
                                        return "finished";
                                    case 21:
                                        return "certificate_url";
                                    case 22:
                                        return "certificate_status";
                                    case 23:
                                        return "supplemental_data";
                                    case 24:
                                        return "key_update";
                                    case 25:
                                        return "compressed_certificate";
                                    default:
                                        return "UNKNOWN";
                                }
                        }
                }
            }
            return "message_hash";
        }
        return "encrypted_extensions";
    }

    public static String getText(short s) {
        return getName(s) + "(" + ((int) s) + ")";
    }

    public static boolean isRecognized(short s) {
        if (s == 8 || s == 254) {
            return true;
        }
        switch (s) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
                return true;
            default:
                switch (s) {
                    case 11:
                    case 12:
                    case 13:
                    case 14:
                    case 15:
                    case 16:
                        return true;
                    default:
                        switch (s) {
                            case 20:
                            case 21:
                            case 22:
                            case 23:
                            case 24:
                            case 25:
                                return true;
                            default:
                                return false;
                        }
                }
        }
    }
}