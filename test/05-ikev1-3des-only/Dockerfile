FROM hwdsl2/ipsec-vpn-server:latest

# Libreswan 5 removed single DES. 3DES is the oldest weak cipher still
# provided by this image, so use it as the legacy-cipher-only target.
RUN set -eux; \
    awk ' \
      /grep -m 1 -Po/ { \
        print "[ -z \"$NET_IFACE\" ] && NET_IFACE=$(ip -4 route list 0/0 2>/dev/null | grep -m 1 -o \"dev [^ ]*\" | cut -d \" \" -f 2)"; \
        next \
      } \
      /^  (leftxauthserver|rightxauthclient)=/ { next } \
      /^ike_algs=/ { \
        print "ike_algs=\"3des-sha1;modp2048\""; \
        next \
      } \
      /^  phase2alg=/ { \
        print "  phase2alg=3des-sha1"; \
        next \
      } \
      /^exec \/usr\/sbin\/xl2tpd/ { \
        print "iptables -I INPUT 1 -p udp --dport 500 -m u32 --u32 \"0>>22&0x3C@25>>24&0xFF=0x20\" -j DROP"; \
        print "iptables -I INPUT 1 -p udp --dport 4500 -m u32 --u32 \"0>>22&0x3C@29>>24&0xFF=0x20\" -j DROP"; \
      } \
      { print } \
    ' /opt/src/run.sh > /tmp/run.sh; \
    mv /tmp/run.sh /opt/src/run.sh; \
    chmod 755 /opt/src/run.sh; \
    grep -Fq "ike_algs=\"3des-sha1;modp2048\"" /opt/src/run.sh
