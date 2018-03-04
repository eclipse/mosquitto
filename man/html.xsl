<!-- Set parameters for manpage xsl -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
	<xsl:import href="/usr/share/xml/docbook/stylesheet/docbook-xsl/html/docbook.xsl"/>
	<xsl:output encoding="utf-8" indent="yes"/>
	<xsl:param name="html.stylesheet">man.css</xsl:param>
	<!-- Generate ansi style function synopses. -->
	<xsl:param name="man.funcsynopsis.style">ansi</xsl:param>
	<xsl:param name="funcsynopsis.style">ansi</xsl:param>
	<xsl:param name="make.clean.html" select="1"></xsl:param>
	<xsl:param name="make.valid.html" select="1"></xsl:param>
	<xsl:param name="html.cleanup" select="1"></xsl:param>
	<xsl:param name="docbook.css.source"></xsl:param>
</xsl:stylesheet>
