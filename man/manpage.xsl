<!-- Set parameters for manpage xsl -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
	<xsl:import href="/usr/share/sgml/docbook/xsl-ns-stylesheets-1.78.1/manpages/docbook.xsl"/>
	<xsl:strip-space elements="member"/>
	<!-- Don't display notes list of link urls. -->
	<xsl:param name="man.endnotes.list.enabled">0</xsl:param>
	<xsl:param name="man.endnotes.are.numbered">0</xsl:param>
	<!-- But if we do, set a base url for the relative links. -->
	<xsl:param name="man.base.url.for.relative.links">http://mosquitto.org/man/</xsl:param>
	<!-- Don't output filename when generating. -->
	<xsl:param name="man.output.quietly" select="1"></xsl:param>
	<!-- Generate ansi style function synopses. -->
	<xsl:param name="man.funcsynopsis.style">ansi</xsl:param>
</xsl:stylesheet>
