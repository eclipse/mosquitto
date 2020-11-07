include ../config.mk

.PHONY : all clean install uninstall dist 

MANPAGES = \
	libmosquitto.3 \
	mosquitto-tls.7 \
	mosquitto.8 \
	mosquitto.conf.5 \
	mosquitto_ctrl.1 \
	mosquitto_ctrl_dynsec.1 \
	mosquitto_passwd.1 \
	mosquitto_pub.1 \
	mosquitto_rr.1 \
	mosquitto_sub.1 \
	mqtt.7

all :  ${MANPAGES}

clean :

reallyclean : clean
	-rm -f *.orig
	-rm -f ${MANPAGES}

dist : ${MANPAGES}

install :
	$(INSTALL) -d "${DESTDIR}$(mandir)/man8"
	$(INSTALL) -m 644 mosquitto.8 "${DESTDIR}${mandir}/man8/mosquitto.8"
	$(INSTALL) -d "${DESTDIR}$(mandir)/man5"
	$(INSTALL) -m 644 mosquitto.conf.5 "${DESTDIR}${mandir}/man5/mosquitto.conf.5"
	$(INSTALL) -d "${DESTDIR}$(mandir)/man1"
	$(INSTALL) -m 644 mosquitto_ctrl.1 "${DESTDIR}${mandir}/man1/mosquitto_ctrl.1"
	$(INSTALL) -m 644 mosquitto_ctrl_dynsec.1 "${DESTDIR}${mandir}/man1/mosquitto_ctrl_dynsec.1"
	$(INSTALL) -m 644 mosquitto_passwd.1 "${DESTDIR}${mandir}/man1/mosquitto_passwd.1"
	$(INSTALL) -m 644 mosquitto_pub.1 "${DESTDIR}${mandir}/man1/mosquitto_pub.1"
	$(INSTALL) -m 644 mosquitto_sub.1 "${DESTDIR}${mandir}/man1/mosquitto_sub.1"
	$(INSTALL) -m 644 mosquitto_rr.1 "${DESTDIR}${mandir}/man1/mosquitto_rr.1"
	$(INSTALL) -d "${DESTDIR}$(mandir)/man7"
	$(INSTALL) -m 644 mqtt.7 "${DESTDIR}${mandir}/man7/mqtt.7"
	$(INSTALL) -m 644 mosquitto-tls.7 "${DESTDIR}${mandir}/man7/mosquitto-tls.7"
	$(INSTALL) -d "${DESTDIR}$(mandir)/man3"
	$(INSTALL) -m 644 libmosquitto.3 "${DESTDIR}${mandir}/man3/libmosquitto.3"

uninstall :
	-rm -f "${DESTDIR}${mandir}/man8/mosquitto.8"
	-rm -f "${DESTDIR}${mandir}/man5/mosquitto.conf.5"
	-rm -f "${DESTDIR}${mandir}/man1/mosquitto_ctrl.1"
	-rm -f "${DESTDIR}${mandir}/man1/mosquitto_ctrl_dynsec.1"
	-rm -f "${DESTDIR}${mandir}/man1/mosquitto_passwd.1"
	-rm -f "${DESTDIR}${mandir}/man1/mosquitto_pub.1"
	-rm -f "${DESTDIR}${mandir}/man1/mosquitto_sub.1"
	-rm -f "${DESTDIR}${mandir}/man1/mosquitto_rr.1"
	-rm -f "${DESTDIR}${mandir}/man7/mqtt.7"
	-rm -f "${DESTDIR}${mandir}/man7/mosquitto-tls.7"
	-rm -f "${DESTDIR}${mandir}/man3/libmosquitto.3"

mosquitto.8 : mosquitto.8.xml manpage.xsl
	$(XSLTPROC) $<

mosquitto.conf.5 : mosquitto.conf.5.xml manpage.xsl
	$(XSLTPROC) $<

mosquitto_ctrl.1 : mosquitto_ctrl.1.xml manpage.xsl
	$(XSLTPROC) $<

mosquitto_ctrl_dynsec.1 : mosquitto_ctrl_dynsec.1.xml manpage.xsl
	$(XSLTPROC) $<

mosquitto_passwd.1 : mosquitto_passwd.1.xml manpage.xsl
	$(XSLTPROC) $<

mosquitto_pub.1 : mosquitto_pub.1.xml manpage.xsl
	$(XSLTPROC) $<

mosquitto_sub.1 : mosquitto_sub.1.xml manpage.xsl
	$(XSLTPROC) $<

mosquitto_rr.1 : mosquitto_rr.1.xml manpage.xsl
	$(XSLTPROC) $<

mqtt.7 : mqtt.7.xml manpage.xsl
	$(XSLTPROC) $<

mosquitto-tls.7 : mosquitto-tls.7.xml manpage.xsl
	$(XSLTPROC) $<

libmosquitto.3 : libmosquitto.3.xml manpage.xsl
	$(XSLTPROC) $<

html : *.xml
	set -e; for m in *.xml; \
		do \
		hfile=$$(echo $${m} | sed -e 's#\(.*\)\.xml#\1#' | sed -e 's/\./-/g'); \
		$(XSLTPROC) html.xsl $${m} > $${hfile}.html; \
	done

potgen :
	 xml2po -o po/mosquitto/mosquitto.8.pot mosquitto.8.xml
	 xml2po -o po/mosquitto.conf/mosquitto.conf.5.pot mosquitto.conf.5.xml
	 xml2po -o po/mosquitto_ctrl/mosquitto_ctrl.1.pot mosquitto_ctrl.1.xml
	 xml2po -o po/mosquitto_ctrl/mosquitto_ctrl_dynsec.1.pot mosquitto_ctrl_dynsec.1.xml
	 xml2po -o po/mosquitto_passwd/mosquitto_passwd.1.pot mosquitto_passwd.1.xml
	 xml2po -o po/mosquitto_pub/mosquitto_pub.1.pot mosquitto_pub.1.xml
	 xml2po -o po/mosquitto_sub/mosquitto_sub.1.pot mosquitto_sub.1.xml
	 xml2po -o po/mosquitto_sub/mosquitto_rr.1.pot mosquitto_rr.1.xml
	 xml2po -o po/mqtt/mqtt.7.pot mqtt.7.xml
	 xml2po -o po/mosquitto-tls/mosquitto-tls.7.pot mosquitto-tls.7.xml
	 xml2po -o po/libmosquitto/libmosquitto.3.pot libmosquitto.3.xml

# To merge new translations do:
# /usr/bin/xml2po -p de.po chapter1.xml > chapter1.de.xml
