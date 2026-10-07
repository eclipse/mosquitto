# -*- coding: utf-8 -*-

# Copyright © 2012-2014 Roberto Alsina and others.

# Permission is hereby granted, free of charge, to any
# person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the
# Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the
# Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice
# shall be included in all copies or substantial portions of
# the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
# KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
# OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""Implementation of compile_html based on asciidoc.

You will need, of course, to install asciidoc

"""

import codecs
import os
import subprocess

from nikola.plugin_categories import PageCompiler
from nikola.utils import makedirs, req_missing, write_metadata

try:
    from collections import OrderedDict
except ImportError:
    OrderedDict = dict  # NOQA


class CompileDocbookManpage(PageCompiler):
    """Compile docbookmanpage into HTML."""

    name = "docbookmanpage"
    demote_headers = True

    def compile(self, source, dest, is_two_file=True, post=None, lang=None):
        """Compile the source file into HTML and save as dest."""
        makedirs(os.path.dirname(dest))
        if "common/" in source and post is not None:
            post.write_depfile(dest, [], post, lang)
            with open(dest, "wt") as f:
                pass
            return []
        binary = self.site.config.get('XSLTPROC_BINARY', 'xsltproc')
        xslpath = os.path.join(os.path.split(__file__)[0], 'html.xsl')
        try:
            source = os.path.abspath(source)
            dest = os.path.abspath(dest)
            xslpath = os.path.abspath(xslpath)
            subprocess.check_call((binary, '--xinclude', '-o', dest, xslpath, source))
            if post is None:
                if shortcode_deps:
                    self.logger.error(
                        "Cannot save dependencies for post {0} (post unknown)",
                        source)
        except OSError as e:
            print(e)
            req_missing(['xsltproc'], 'build this site (compile with xsltproc)', python=False)

    def create_post(self, path, content=None, onefile=False, is_page=False, **kw):
        """Create post file with optional metadata."""
        metadata = OrderedDict()
        metadata.update(self.default_metadata)
        metadata.update(kw)
        makedirs(os.path.dirname(path))
        if not content.endswith('\n'):
            content += '\n'
        with codecs.open(path, "wb+", "utf8") as fd:
            if onefile:
                fd.write("////\n")
                fd.write(write_metadata(metadata))
                fd.write("////\n")
            fd.write(content)
