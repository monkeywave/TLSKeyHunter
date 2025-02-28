package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public class ExtensionType {
    public static final int application_layer_protocol_negotiation = 16;
    public static final int cached_info = 25;
    public static final int cert_type = 9;
    public static final int certificate_authorities = 47;
    public static final int client_authz = 7;
    public static final int client_certificate_type = 19;
    public static final int client_certificate_url = 2;
    public static final int compress_certificate = 27;
    public static final int connection_id = 54;
    public static final int cookie = 44;
    public static final int early_data = 42;
    public static final int ec_point_formats = 11;
    public static final int encrypt_then_mac = 22;
    public static final int extended_master_secret = 23;
    public static final int heartbeat = 15;
    public static final int key_share = 51;
    public static final int max_fragment_length = 1;
    public static final int oid_filters = 48;
    public static final int padding = 21;
    public static final int post_handshake_auth = 49;
    public static final int pre_shared_key = 41;
    public static final int psk_key_exchange_modes = 45;
    public static final int record_size_limit = 28;
    public static final int renegotiation_info = 65281;
    public static final int server_authz = 8;
    public static final int server_certificate_type = 20;
    public static final int server_name = 0;
    public static final int session_ticket = 35;
    public static final int signature_algorithms = 13;
    public static final int signature_algorithms_cert = 50;
    public static final int signed_certificate_timestamp = 18;
    public static final int srp = 12;
    public static final int status_request = 5;
    public static final int status_request_v2 = 17;
    public static final int supported_groups = 10;
    public static final int supported_versions = 43;
    public static final int token_binding = 24;
    public static final int truncated_hmac = 4;
    public static final int trusted_ca_keys = 3;
    public static final int use_srtp = 14;
    public static final int user_mapping = 6;

    public static String getName(int i) {
        if (i != 27) {
            if (i != 28) {
                if (i != 35) {
                    if (i != 54) {
                        if (i != 65281) {
                            switch (i) {
                                case 0:
                                    return "server_name";
                                case 1:
                                    return "max_fragment_length";
                                case 2:
                                    return "client_certificate_url";
                                case 3:
                                    return "trusted_ca_keys";
                                case 4:
                                    return "truncated_hmac";
                                case 5:
                                    return "status_request";
                                case 6:
                                    return "user_mapping";
                                case 7:
                                    return "client_authz";
                                case 8:
                                    return "server_authz";
                                case 9:
                                    return "cert_type";
                                case 10:
                                    return "supported_groups";
                                case 11:
                                    return "ec_point_formats";
                                case 12:
                                    return "srp";
                                case 13:
                                    return "signature_algorithms";
                                case 14:
                                    return "use_srtp";
                                case 15:
                                    return "heartbeat";
                                case 16:
                                    return "application_layer_protocol_negotiation";
                                case 17:
                                    return "status_request_v2";
                                case 18:
                                    return "signed_certificate_timestamp";
                                case 19:
                                    return "client_certificate_type";
                                case 20:
                                    return "server_certificate_type";
                                case 21:
                                    return "padding";
                                case 22:
                                    return "encrypt_then_mac";
                                case 23:
                                    return "extended_master_secret";
                                case 24:
                                    return "token_binding";
                                case 25:
                                    return "cached_info";
                                default:
                                    switch (i) {
                                        case 41:
                                            return "pre_shared_key";
                                        case 42:
                                            return "early_data";
                                        case 43:
                                            return "supported_versions";
                                        case 44:
                                            return "cookie";
                                        case 45:
                                            return "psk_key_exchange_modes";
                                        default:
                                            switch (i) {
                                                case 47:
                                                    return "certificate_authorities";
                                                case 48:
                                                    return "oid_filters";
                                                case 49:
                                                    return "post_handshake_auth";
                                                case 50:
                                                    return "signature_algorithms_cert";
                                                case 51:
                                                    return "key_share";
                                                default:
                                                    return "UNKNOWN";
                                            }
                                    }
                            }
                        }
                        return "renegotiation_info";
                    }
                    return "connection_id";
                }
                return "session_ticket";
            }
            return "record_size_limit";
        }
        return "compress_certificate";
    }

    public static String getText(int i) {
        return getName(i) + "(" + i + ")";
    }

    public static boolean isRecognized(int i) {
        if (i == 27 || i == 28 || i == 35 || i == 54 || i == 65281) {
            return true;
        }
        switch (i) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
            case 15:
            case 16:
            case 17:
            case 18:
            case 19:
            case 20:
            case 21:
            case 22:
            case 23:
            case 24:
            case 25:
                return true;
            default:
                switch (i) {
                    case 41:
                    case 42:
                    case 43:
                    case 44:
                    case 45:
                        return true;
                    default:
                        switch (i) {
                            case 47:
                            case 48:
                            case 49:
                            case 50:
                            case 51:
                                return true;
                            default:
                                return false;
                        }
                }
        }
    }
}