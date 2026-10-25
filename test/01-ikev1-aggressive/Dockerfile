FROM hwdsl2/ipsec-vpn-server:latest

# The upstream image enables IKEv1/XAuth but not Aggressive Mode.
# Aggressive Mode requires one fully specified proposal and one DH group.
# Unlike the group-ID scenario, this target uses IKESS's neutral probe identity,
# so callers do not need to know or supply a VPN group ID.
RUN set -eux; \
    awk ' \
      /grep -m 1 -Po/ { \
        print "[ -z \"$NET_IFACE\" ] && NET_IFACE=$(ip -4 route list 0/0 2>/dev/null | grep -m 1 -o \"dev [^ ]*\" | cut -d \" \" -f 2)"; \
        next \
      } \
      /^  (leftxauthserver|rightxauthclient)=/ { next } \
      /^ike_algs=/ { \
          print "ike_algs=\"aes256-sha1;modp2048\""; \
        next \
      } \
      /^  phase2alg=/ { \
          print "  phase2alg=aes256-sha1"; \
        next \
      } \
      $0 == "conn xauth-psk" { \
        print; \
        print "  aggressive=yes"; \
        print "  rightid=@ikess-probe.invalid"; \
        next \
      } \
      $0 ~ /^%any  %any  : PSK/ { \
        print "%any  @ikess-probe.invalid : PSK \"$VPN_IPSEC_PSK\""; \
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
    grep -Fq "  aggressive=yes" /opt/src/run.sh
