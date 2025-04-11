https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_SSL

man kann neben mbedtls noch andere habe
cat /etc/lighttpd/conf-available/10-mbedtls.conf
# /usr/share/doc/lighttpd/ssl.txt
# -*- conflicts: gnutls, nss, ssl, wolfssl -*-

server.modules += ( "mod_mbedtls" )

# ssl.* in global scope gets inherited by
#   $SERVER["socket"] == "..." { ssl.engine = "enable" }
ssl.pemfile = "/etc/lighttpd/server.pem"

$SERVER["socket"] == "0.0.0.0:443" {
	ssl.engine  = "enable"
}
include_shell "/usr/share/lighttpd/use-ipv6.pl 443"
