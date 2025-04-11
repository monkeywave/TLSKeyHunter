# Real world examples

These real-world examples demonstrate TLS key extraction across diverse environments and implementations. The binaries are available at [Zenodo](https://zenodo.org/records/15188139?preview=1&token=eyJhbGciOiJIUzUxMiJ9.eyJpZCI6IjRiM2ZmZjlmLTFkYzgtNDVmMi1iODA4LTY2MDQxODI5NjQ4MiIsImRhdGEiOnt9LCJyYW5kb20iOiJlZGVkZWI1MzVjYTk5MTgwNjU5MDk4N2U5MTc2MDM3YyJ9.CWkv3gZcoQp-sZPTN2cZ1hMT0avpQMgaF61NEwjPSohKShauGsfVfl92P79gF7uAgTX0ISXkMwUmP1qN1EsXPg).


## Environment

We evaluated on a Ubuntu machine the following setup


Resulting in the following example applications:
- Firefox (NSS)
- Docker (GoTLS)
- Chrome (BoringSSL)
- Powershell (Schannel)
- Curl (GnuTLS)
- lighttpd-mod-mbedtls (MBedtTLS) ? nur TLS 1.2 support