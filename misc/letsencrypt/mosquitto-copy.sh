#!/bin/sh

# This is an example deploy renewal hook for certbot that copies newly updated
# certificates to the Mosquitto certificates directory and sets the ownership
# and permissions so only the mosquitto user can access them, then signals
# Mosquitto to reload certificates.

# RENEWED_DOMAINS will match the domains being renewed for that certificate, so
# may be just "example.com", or multiple domains "www.example.com example.com"
# depending on your certificate.

# Place this script in /etc/letsencrypt/renewal-hooks/deploy/ and make it
# executable after editing it to your needs.

# Set which domain this script will be run for
MY_DOMAIN=example.com
# Set the directory that the certificates will be copied to.
CERTIFICATE_DIR=/etc/mosquitto/certs

if [ "${RENEWED_DOMAINS}" = "${MY_DOMAIN}" ]; then
	# Copy new certificate to Mosquitto directory
	cp ${RENEWED_LINEAGE}/fullchain.pem ${CERTIFICATE_DIR}/server.pem
	cp ${RENEWED_LINEAGE}/privkey.pem ${CERTIFICATE_DIR}/server.key

	# Set ownership to Mosquitto
	chown mosquitto: ${CERTIFICATE_DIR}/server.pem ${CERTIFICATE_DIR}/server.key

	# Ensure permissions are restrictive
	chmod 0600 ${CERTIFICATE_DIR}/server.pem ${CERTIFICATE_DIR}/server.key

	# Tell Mosquitto to reload certificates and configuration
	pkill -HUP -x mosquitto
fi
