FROM hwdsl2/ipsec-vpn-server:latest

# Libreswan still parses IKEv1 and returns NO_PROPOSAL when no IKEv1
# connection is loaded. Drop IKEv1 packets so this is a strict IKEv2-only
# discovery target on both the standard and NAT-T ports.
RUN set -eux; \
    awk ' \
      /grep -m 1 -Po/ { \
        print "[ -z \"$NET_IFACE\" ] && NET_IFACE=$(ip -4 route list 0/0 2>/dev/null | grep -m 1 -o \"dev [^ ]*\" | cut -d \" \" -f 2)"; \
        next \
      } \
      /^exec \/usr\/sbin\/xl2tpd/ { \
        print "iptables -I INPUT 1 -p udp --dport 500 -m u32 --u32 \"0>>22&0x3C@25>>24&0xFF=0x10\" -j DROP"; \
        print "iptables -I INPUT 1 -p udp --dport 4500 -m u32 --u32 \"0>>22&0x3C@29>>24&0xFF=0x10\" -j DROP"; \
      } \
      { print } \
    ' /opt/src/run.sh > /tmp/run.sh; \
    mv /tmp/run.sh /opt/src/run.sh; \
    chmod 755 /opt/src/run.sh