#!/usr/bin/python3
# -*- coding: utf-8 -*-

'''
randomInverse is a Pyshark based program to identify the CLIENT_RANDOM from a TLS session from a PCAP and its correspondig keys
'''

from scapy.all import *
from scapy.layers.tls.all import TLS
from scapy.layers.tls.all import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_SupportedVersion_CH


from dataclasses import dataclass
from typing import Optional, List, Dict

import tempfile
import pyshark
import os
import sys

@dataclass
class ClientRandomResult:
    is_tls12: bool
    is_tls13: bool
    version_str: str
    client_random: str

@dataclass
class NssResult:
    client_random_hex: ClientRandomResult
    secret_info_list: List[Dict[str, str]]

class RandomInverse():

    TLS_VERSION_MAP = {
        "0x0301": "TLS 1.0",
        "0x0302": "TLS 1.1",
        "0x0303": "TLS 1.2",
        "0x0304": "TLS 1.3",
        "0x0300": "SSLv3"   # for completeness, if encountered
    }

    def __init__(self, keylogfile, pcap_name):
        self.client_random_map = {}
        self.keylog_file = keylogfile
        self.pcap_name = pcap_name
        self.streams = set() # saves tcp streams of the 
    
    def get_full_decryption_results(self, nss_result_list) -> List:
        final_keylog_entries = []

        for nss_result in nss_result_list:
            client_random_hex = nss_result.client_random_hex
        
            for entry in nss_result.secret_info_list:
                    label = entry["label"]
                    secret_hex = entry["secret_hex"]
                    # Append lines in NSS key log format, e.g.:
                    #   CLIENT_RANDOM <client_random_hex> <secret_hex>
                    #   CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random_hex> <secret_hex>, etc.
                    final_keylog_entries.append(f"{label} {client_random_hex} {secret_hex}")
                    #print(f"{label} {client_random_hex} {secret_hex}")
        
        return final_keylog_entries


    
    def write_temp_keylog_file(self, isTLS13, client_random_hex, secret_info, keylog_fname):
        """
        Writes a minimal key log file. If TLS 1.2, one line. If TLS 1.3, four lines.
        """
        with open(keylog_fname, "w") as f:
            for entry in secret_info:
                label = entry.get("label")
                secret_hex = entry.get("secret_hex")
                if label and secret_hex:
                    # Write the line in NSS key log format
                    f.write(f"{label} {client_random_hex} {secret_hex}\n")
                    #print(f"{label} {client_random_hex} {secret_hex}")
                elif label is None:
                    if isTLS13 == False:
                        # TLS 1.2
                        f.write(f"CLIENT_RANDOM {client_random_hex} {secret_info[0]["secret_hex"]}\n")
                    elif isTLS13:
                        f.write(f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {client_random_hex} {secret_info[0]["secret_hex"]}\n")
                        f.write(f"SERVER_HANDSHAKE_TRAFFIC_SECRET {client_random_hex} {secret_info[1]["secret_hex"]}\n")
                        f.write(f"CLIENT_TRAFFIC_SECRET_0 {client_random_hex} {secret_info[2]["secret_hex"]}\n")
                        f.write(f"SERVER_TRAFFIC_SECRET_0 {client_random_hex} {secret_info[3]["secret_hex"]}\n")


    def test_decryption_with_pyshark(self, client_random_result, secret_info) -> bool:

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            keylog_fname = tmp.name
        
        success = False
        
        try:
            client_random_hex = client_random_result.client_random
            isTLS13 = client_random_result.is_tls13

            # Write lines to the keylog file
            #client_random_hex = "A2B93C266939819873655DE4C4B4B4B4B4B4B4B4B4B4B4B4B4B4B4B4B4B4B4BA"
            print(f"[+] Trying {client_random_hex} ...")
            self.write_temp_keylog_file(isTLS13, client_random_hex, secret_info, keylog_fname)

            for stream_id in self.streams:
                # Launch pyshark with temp keylog file
                cap = pyshark.FileCapture(self.pcap_name, display_filter=f'tcp.stream == {stream_id}', decode_as={}, override_prefs={"tls.keylog_file": keylog_fname})

                # Check some packets
                MAX_PACKETS = 2000
                for i, pkt in enumerate(cap):
                    if i > MAX_PACKETS:
                        break
                    
                    if 'TLS' in pkt:
                        layer_names = [ly.layer_name for ly in pkt.layers]
                            
                        if "tls" in layer_names:

                            if layer_names[-1] != 'tls':
                                #print("[!] Found CLIENT_RANDOM")
                                return True

                cap.close()
        finally:
            if os.path.exists(keylog_fname):
                os.remove(keylog_fname)
        
        return success

    
    def parse_partial_secret_file(self):
        """
        Reads all non-comment lines from the provided keylog file and splits them into groups.
        A new group starts whenever a line's label (i.e., the first token) begins
        with 'CLIENT_RANDOM' or 'CLIENT_HANDSHAKE_TRAFFIC_SECRET'.
        
        Each group is a list of dicts of the form:
        {
            "label": <string_or_None>,
            "secret_hex": <string_of_hex_bytes>
        }
        The function returns a list of these groups, e.g.:
        [
        [ {"label": "CLIENT_RANDOM", "secret_hex": "AAAAAA..."}, {...} ],
        [ {"label": "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "secret_hex": "BBBBBB..."}, {...} ],
        ...
        ]
        """

        groups = []
        current_group = []

        # Define the labels that should trigger a new group
        group_start_labels = ("CLIENT_RANDOM", "CLIENT_HANDSHAKE_TRAFFIC_SECRET")

        with open(self.keylog_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) == 1:
                    entry = {"label": None, "secret_hex": parts[0]}
                elif len(parts) == 2:
                    entry = {"label": parts[0], "secret_hex": "".join(parts[1:])}
                elif len(parts) == 3:
                    entry = {"label": parts[0], "secret_hex": "".join(parts[2:])}

                if entry["label"] is not None and entry["label"].startswith(group_start_labels):
                    # If we already have some lines in the current_group, save it
                    if current_group:
                        groups.append(current_group)
                    # Start a fresh group
                    current_group = [entry]
                else:
                    # Continue adding to the current group
                    current_group.append(entry)

        if current_group:
            groups.append(current_group)
        
        return groups


    def handle_tls(self, pkt) -> Optional[ClientRandomResult]:
        """
        Extracts fields from a TLS ClientHello, if available:
        - handshake_random
        - handshake_extensions_supported_version
        Then prints them in a style similar to the original TLS script.
        """
        client_random_hex = pkt.tls.get_field_value("handshake_random").replace(":", "").upper()
        raw_supported_versions = pkt.tls.get_field_value("handshake_extensions_supported_version")
        if raw_supported_versions is None:
            supported_versions = []
            #tls_layer = pkt['TLS']
            #print(tls_layer.field_names)
            raw_supported_versions = pkt.tls.get_field_value("handshake_version")
            supported_versions.append(raw_supported_versions)
        elif isinstance(raw_supported_versions, list):
            supported_versions = raw_supported_versions
        else:
            supported_versions = [v.strip() for v in raw_supported_versions.split(",")]
        
        versions_str = self.interpret_versions(supported_versions)
        print(f"[!] Client Random: {client_random_hex}")
        print(f"[!] Versions: {versions_str}")
        #print("-------------TLS-------------------")
        is_tls12 = "TLS 1.2" in versions_str
        is_tls13 = "TLS 1.3" in versions_str
        
        return ClientRandomResult(
            is_tls12=is_tls12,
            is_tls13=is_tls13,
            version_str=versions_str,
            client_random=client_random_hex
        )
    

    def handle_dtls(self, pkt) -> Optional[ClientRandomResult]:
        """
        Extracts fields from a DTLS ClientHello, if available:
        - dtls.handshake.random
        - dtls.handshake.extensions.supported_version (not always used or present in DTLS)
        The actual fields may vary depending on your Wireshark/Pyshark version 
        and DTLS handshake structure. Adjust accordingly.
        """
        # For demonstration, we assume dtls.handshake.random and dtls.handshake.extensions.supported_version
        client_random_hex = pkt.dtls.get_field_value("handshake_random").replace(":", "").upper()
        if client_random_hex is None:
            client_random_hex = "(no random found)"
        # If there's a "dtls.handshake.extensions.supported_version" field (uncommon in older DTLS):
        raw_supported_versions = pkt.dtls.get_field_value("handshake_extensions_supported_version")
        if raw_supported_versions is None:
            supported_versions = []
        elif isinstance(raw_supported_versions, list):
            supported_versions = raw_supported_versions
        else:
            supported_versions = [v.strip() for v in raw_supported_versions.split(",")]
        
        versions_str = self.interpret_versions(supported_versions)
        print(f"[!] Client Random: {client_random_hex}")
        print(f"[!] Versions: {versions_str}")
        
        is_tls12 = "TLS 1.2" in versions_str
        is_tls13 = "TLS 1.3" in versions_str
        
        return ClientRandomResult(
            is_tls12=is_tls12,
            is_tls13=is_tls13,
            version_str=versions_str,
            client_random=client_random_hex
        )
    
    
    def handle_quic(self, pkt) -> Optional[ClientRandomResult]:
        """
        Extracts QUIC version info from a QUIC packet, if available.
        In Wireshark/Pyshark, the field might be 'quic.version' or 'quic.long_header.version'.
        We'll search generically for 'quic.version'.
        """
        #tls_layer = pkt['QUIC']
        #print(tls_layer.field_names)
        client_random_hex = pkt.quic.get_field_value("tls_handshake_random").replace(":", "").upper()
        if client_random_hex is None:
            client_random_hex = "(no random found)"

        raw_quic_version = pkt.quic.tls_handshake_extensions_supported_version
        if raw_quic_version is None:
            supported_versions = []
        elif isinstance(raw_quic_version, list):
            supported_versions = raw_quic_version
        else:
            supported_versions = [v.strip() for v in raw_quic_version.split(",")]
        
        versions_str = self.interpret_versions(supported_versions)
        if not versions_str:
            versions_str = "(no version found)"
        
        print(f"[!] (QUIC)Client Random: {client_random_hex}")
        print(f"[!] (QUIC)Version: {versions_str}")

        is_tls12 = "TLS 1.2" in versions_str
        is_tls13 = "TLS 1.3" in versions_str
        
        return ClientRandomResult(
            is_tls12=is_tls12,
            is_tls13=is_tls13,
            version_str=versions_str,
            client_random=client_random_hex
        )
    

    def interpret_versions(self, versions: List[str]) -> str:
        """
        Takes a list of version strings like ["0x0303", "0x0302", "0x0301"]
        and converts them to human-readable names. The first version in the list
        is usually the highest or most preferred.
        
        If the list is e.g. ["0x0303", "0x0302", "0x0301"],
        it returns "TLS 1.2 (supports TLS 1.1, TLS 1.0)".
        """
        if not versions:
            return "No supported versions"

        # Convert hex codes to readable strings using TLS_VERSION_MAP
        parsed = []
        for v in versions:
            parsed.append(RandomInverse.TLS_VERSION_MAP.get(v, v))  # fallback to original if unknown

        # The first is typically the highest or the first the client listed
        highest = parsed[0]
        others = parsed[1:]

        if others:
            print(f"[!] {highest} (supports {', '.join(others)})")
        return highest

    
    def extract_client_hellos(self) -> List[ClientRandomResult]:
        cap = pyshark.FileCapture(
            input_file=self.pcap_name,
            display_filter="tls.handshake.type == 1"  # filter on ClientHello
        )
        client_random_list: List[ClientRandomResult] = []


        for pkt in cap: 
            if 'TCP' in pkt:
                self.streams.add(int(pkt.tcp.stream))
            if 'UDP' in pkt:
                #print(pkt.udp.stream)
                #stream_id = f"UDP_{pkt.udp.srcport}-{pkt.udp.dstport}"
                self.streams.add(int(pkt.udp.stream))

            if 'TLS' in pkt:
                layer_names = [ly.layer_name for ly in pkt.layers]
                if "tls" in layer_names:
                    hs_type = pkt.tls.get_field_value("handshake_type")
                    if hs_type == "1" or (isinstance(hs_type, list) and "1" in hs_type):
                        result = self.handle_tls(pkt)
            elif 'DTLS' in pkt:
                hs_type = pkt.dtls.get_field_value("handshake_type")
                if hs_type == "1" or (isinstance(hs_type, list) and "1" in hs_type):
                    result = self.handle_dtls(pkt)
            elif "QUIC" in pkt:
                result = self.handle_quic(pkt)
            
            if result is not None:
                client_random_list.append(result)


        cap.close()
        return client_random_list
    
    def extract_client_random_via_scapy(self):
        bind_layers(TCP, TLS, dport=44330) # to handle TLS traffic on none standard ports
        packets = rdpcap(self.pcap_name)
        sessions = {}  # Maps (src, dst, sport, dport) to TLS sessions

        for pkt in packets:
            #print(pkt)
            if not (pkt.haslayer(TCP) and pkt.haslayer(TLSClientHello)):
                continue

            ip = pkt[IP]
            tcp = pkt[TCP]
            conn_key = (ip.src, ip.dst, tcp.sport, tcp.dport)
            client_hello = pkt[TLSClientHello]

            tls_version = None
            legacy_version = client_hello.version  # Legacy TLS version (e.g., 0x0303 for TLS 1.2)

            if 0x0304 == legacy_version:  # 0x0304 = TLS 1.3
                tls_version = "TLS 1.3"
            else:
                tls_version = "TLS 1.2 or below"

            client_random = client_hello.gmt_unix_time.to_bytes(4, 'big') + client_hello.random_bytes

            if client_hello.haslayer(TLS_Ext_SupportedVersion_CH):
                    ext = client_hello.getlayer(TLS_Ext_SupportedVersion_CH)
                    print("Found TLS_Ext_SupportedVersion_CH extension")

                    # Print the entire extension for debugging
                    # ext.show()  # Uncomment if you want to see all fields

                    # The extension typically has a 'versions' field listing supported versions.
                    # For example, 0x0303 => TLS 1.2, 0x0304 => TLS 1.3, etc.
                    supported_versions = getattr(ext, "versions", [])
                    print("Supported Versions:", supported_versions)
                    
                    # Check if TLS 1.2 or TLS 1.3 is supported
                    if 0x0303 in supported_versions:
                        print("TLS 1.2 is supported by this Client Hello.")
                    if 0x0304 in supported_versions:
                        print("TLS 1.3 is supported by this Client Hello.")
                    print("----")



            print(f"Detected {tls_version} session")
            print(f"Client_Random from PCAP: {client_random.hex().upper()}")
            for ext in client_hello.ext:
                #print(f"ext: {ext}")
                print(type(ext))
                #sys.stdout.buffer.write(ext)
            sys.exit(1)

            """

            # Check for ClientHello to extract client_random
            if TLSClientHello in tls_data:
                ch = tls_data[TLSClientHello]
                client_random = ch.gmt_unix_time.to_bytes(4, 'big') + ch.random_bytes

                legacy_version = ch.version  # Legacy field (TLS 1.3 uses 0x0303 here)
                tls_version = None

                # Check for TLS 1.3's "supported_versions" extension
                if TLSExtSupportedVersions in ch:
                    ext = ch[TLSExtSupportedVersions]
                    if 0x0304 in ext.versions:  # 0x0304 = TLS 1.3
                        tls_version = "TLS 1.3"
                    else:
                        tls_version = "TLS 1.2 or below"
                else:
                    # Fallback to legacy version
                    tls_version = "TLS 1.2" if legacy_version == 0x0303 else "TLS 1.2 or below"
                
                print(f"Detected {tls_version} session")
                sys.exit(1)

            """


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <pcap_file> <secret_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    secret_file = sys.argv[2]
    nss_result_list = []

    #randomInverse = RandomInverse("keylogfile.txt","tls.pcap")
    print("randomInverse v. 0.3")
    print(f"[+] Starting to parse {pcap_file} ...")
    #randomInverse = RandomInverse("httpsslkeys.log","sample_captures/http-chunked-ssl.pcapng")
    randomInverse = RandomInverse(secret_file,pcap_file)
    secret_infos = randomInverse.parse_partial_secret_file()

    client_random_results_list = randomInverse.extract_client_hellos()

    for secret_info in secret_infos:
        print(f"\n[+] Trying to identify client random for: {secret_info[0]["label"]} ?...? {secret_info[0]["secret_hex"]}")
        for i,client_random_result in enumerate(client_random_results_list):
            found_random = randomInverse.test_decryption_with_pyshark(client_random_result ,secret_info)
            if found_random:
                tmpNssResult = NssResult(
                    client_random_hex=client_random_result.client_random,
                    secret_info_list=secret_info
                )

                nss_result_list.append(tmpNssResult)
                client_random_results_list.pop(i)  # remove it from the list
                break


    final_keylog_entries = randomInverse.get_full_decryption_results(nss_result_list)
    if final_keylog_entries:
        print("\n\nFinal NSS Key Log Format Lines (for all successful matches):\n")
        for line in final_keylog_entries:
            print(line)
        if len(client_random_results_list) > 0:
            print("\n\n[!] Unable to identify the secrets associated with these client random values:")
            for cr in client_random_results_list:
                print(f"[-] {cr.client_random}")
    else:
        print("\n\nNo successful matches found. No final key log lines produced.")
        
    

if __name__ == "__main__":
    main()