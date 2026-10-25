FROM hwdsl2/ipsec-vpn-server:latest

ARG VPN_GROUP_ID=vpn

# Configure a Cisco-style opaque KEY_ID and bind the PSK to that identity.
RUN set -eux; \
    awk -v group="${VPN_GROUP_ID}" ' \
      /grep -m 1 -Po/ { \
        print "[ -z \"$NET_IFACE\" ] && NET_IFACE=$(ip -4 route list 0/0 2>/dev/null | grep -m 1 -o \"dev [^ ]*\" | cut -d \" \" -f 2)"; \
        next \
      } \
      /^  (leftxauthserver|rightxauthclient)=/ { next } \
      /^ike_algs=/ { \
        print "ike_algs=\"aes256-sha2_256;modp2048\""; \
        next \
      } \
      /^  phase2alg=/ { \
        print "  phase2alg=aes256-sha2_256"; \
        next \
      } \
      $0 == "conn xauth-psk" { \
        print; \
        print "  aggressive=yes"; \
        print "  rightid=@[" group "]"; \
        next \
      } \
      $0 ~ /^%any  %any  : PSK/ { \
        print "%any  @[" group "] : PSK \"$VPN_IPSEC_PSK\""; \
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
    grep -Fq "  rightid=@[${VPN_GROUP_ID}]" /opt/src/run.sh; \
    grep -Fq "%any  @[${VPN_GROUP_ID}] : PSK" /opt/src/run.sh
