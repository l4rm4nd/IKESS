FROM hwdsl2/ipsec-vpn-server:latest

# Restrict the IKEv1/XAuth connection to exactly one strong Main Mode
# proposal. IKEv2 remains managed independently by the upstream image.
RUN set -eux; \
    awk ' \
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
      { print } \
    ' /opt/src/run.sh > /tmp/run.sh; \
    mv /tmp/run.sh /opt/src/run.sh; \
    chmod 755 /opt/src/run.sh; \
    grep -Fq "ike_algs=\"aes256-sha2_256;modp2048\"" /opt/src/run.sh; \
    ! grep -Fq "  aggressive=yes" /opt/src/run.sh
