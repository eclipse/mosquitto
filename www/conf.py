# -*- coding: utf-8 -*-

from __future__ import unicode_literals
import time

# !! This is the configuration of Nikola. !! #
# !!  You should edit it to your liking.  !! #


# ! Some settings can be different in different languages.
# ! A comment stating (translatable) is used to denote those.
# ! There are two ways to specify a translatable setting:
# ! (a) BLOG_TITLE = "My Blog"
# ! (b) BLOG_TITLE = {"en": "My Blog", "es": "Mi Blog"}
# ! Option (a) is used when you don't want that setting translated.
# ! Option (b) is used for settings that are different in different languages.


# Data about this site
BLOG_AUTHOR = "Mosquitto Project"  # (translatable)
BLOG_TITLE = "Eclipse Mosquitto"  # (translatable)
# This is the main URL for your site. It will be used
# in a prominent link. Don't forget the protocol (http/https)!
SITE_URL = "https://mosquitto.org/"
# This is the URL where Nikola's output will be deployed.
# If not set, defaults to SITE_URL
# BASE_URL = "https://example.com/"
BLOG_EMAIL = "roger@atchoo.org"
BLOG_DESCRIPTION = "An open source MQTT server"  # (translatable)


# What is the default language?
DEFAULT_LANG = "en"

# What other languages do you have?
# The format is {"translationcode" : "path/to/translation" }
# the path will be used as a prefix for the generated pages location
TRANSLATIONS = {
    DEFAULT_LANG: "",
    # Example for another language:
    # "es": "./es",
}

# What will translated input files be named like?

# If you have a page something.rst, then something.pl.rst will be considered
# its Polish translation.
#     (in the above example: path == "something", ext == "rst", lang == "pl")
# this pattern is also used for metadata:
#     something.meta -> something.pl.meta

TRANSLATIONS_PATTERN = "{path}.{lang}.{ext}"

# Links for the sidebar / navigation bar.  (translatable)
# This is a dict.  The keys are languages, and values are tuples.
#
# For regular links:
#     ('https://getnikola.com/', 'Nikola Homepage')
#
# For submenus:
#     (
#         (
#             ('https://apple.com/', 'Apple'),
#             ('https://orange.com/', 'Orange'),
#         ),
#         'Fruits'
#     )
#
# WARNING: Support for submenus is theme-dependent.
#          Only one level of submenus is supported.
# WARNING: Some themes, including the default Bootstrap 3 theme,
#          may present issues if the menu is too large.
#          (in bootstrap3, the navbar can grow too large and cover contents.)
# WARNING: If you link to directories, make sure to follow
#          ``STRIP_INDEXES``.  If it’s set to ``True``, end your links
#          with a ``/``, otherwise end them with ``/index.html`` — or
#          else they won’t be highlighted when active.

NAVIGATION_LINKS = {
    DEFAULT_LANG: (
        ("/", "Home"),
        #("/about/", "About"),
        ("/blog/", "Blog"),
        ("/download/", "Download"),
        #("/development/", "Development"),
        #("/community/", "Community"),
        #("/sponsoring/", "Sponsoring"),
        (
            (
                ("/documentation/", "All"),
                ("/roadmap/", "Roadmap"),
                ("/api/", "API"),
                ("/man/libmosquitto-3.html", "libmosquitto"),
                ("/man/mosquitto-8.html", "mosquitto"),
                ("/man/mosquitto-conf-5.html", "mosquitto.conf"),
                ("/man/mosquitto_ctrl-1.html", "mosquitto_ctrl"),
                ("/man/mosquitto_ctrl_dynsec-1.html", "mosquitto_ctrl_dynsec"),
                ("/man/mosquitto_passwd-1.html", "mosquitto_passwd"),
                ("/man/mosquitto_pub-1.html", "mosquitto_pub"),
                ("/man/mosquitto_rr-1.html", "mosquitto_rr"),
                ("/man/mosquitto_sub-1.html", "mosquitto_sub"),
                ("/man/mosquitto-tls-7.html", "mosquitto-tls"),
                ("/man/mqtt-7.html", "mqtt"),
            ), "Documentation",
        )
    ),
}

# Name of the theme to use.
THEME = "mosquitto"
#THEME = "bootstrap3"

# Primary color of your theme. This will be used to customize your theme and
# auto-generate related colors in POSTS_SECTION_COLORS. Must be a HEX value.
THEME_COLOR = '#3c5280'

# POSTS and PAGES contains (wildcard, destination, template) tuples.
# (translatable)
#
# The wildcard is used to generate a list of source files
# (whatever/thing.rst, for example).
#
# That fragment could have an associated metadata file (whatever/thing.meta),
# and optionally translated files (example for Spanish, with code "es"):
#     whatever/thing.es.rst and whatever/thing.es.meta
#
#     This assumes you use the default TRANSLATIONS_PATTERN.
#
# From those files, a set of HTML fragment files will be generated:
# cache/whatever/thing.html (and maybe cache/whatever/thing.html.es)
#
# These files are combined with the template to produce rendered
# pages, which will be placed at
# output/TRANSLATIONS[lang]/destination/pagename.html
#
# where "pagename" is the "slug" specified in the metadata file.
# The page might also be placed in /destination/pagename/index.html
# if PRETTY_URLS are enabled.
#
# The difference between POSTS and PAGES is that POSTS are added
# to feeds, indexes, tag lists and archives and are considered part
# of a blog, while PAGES are just independent HTML pages.
#
# Finally, note that destination can be translated, i.e. you can
# specify a different translation folder per language. Example:
#     PAGES = (
#         ("pages/*.rst", {"en": "pages", "de": "seiten"}, "story.tmpl"),
#         ("pages/*.md", {"en": "pages", "de": "seiten"}, "story.tmpl"),
#     )

POSTS = (
    ("posts/*.rst", "blog", "post.tmpl"),
    ("posts/*.txt", "blog", "post.tmpl"),
    ("posts/*.html", "blog", "post.tmpl"),
    ("posts/*.md", "blog", "post.tmpl"),
)
PAGES = (
    ("pages/*.rst", "", "story.tmpl"),
    ("pages/*.txt", "", "story.tmpl"),
    ("pages/*.html", "", "story.tmpl"),
    ("pages/*.md", "", "story.tmpl"),
    ("pages/documentation/*.md", "", "story.tmpl"),
    ("man/*.xml", "man", "story.tmpl"),
)


# Below this point, everything is optional

# Post's dates are considered in UTC by default, if you want to use
# another time zone, please set TIMEZONE to match. Check the available
# list from Wikipedia:
# https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
# (e.g. 'Europe/Zurich')
# Also, if you want to use a different time zone in some of your posts,
# you can use the ISO 8601/RFC 3339 format (ex. 2012-03-30T23:00:00+02:00)
TIMEZONE = "Europe/London"

# If you want to use ISO 8601 (also valid RFC 3339) throughout Nikola
# (especially in new_post), set this to True.
# Note that this does not affect DATE_FORMAT.
# FORCE_ISO8601 = False

# Date format used to display post dates. (translatable)
# (str used by datetime.datetime.strftime)
# DATE_FORMAT = '%Y-%m-%d %H:%M'

# Date format used to display post dates, if local dates are used. (translatable)
# (str used by moment.js)
# JS_DATE_FORMAT = 'YYYY-MM-DD HH:mm'

# Date fanciness.
#
# 0 = using DATE_FORMAT and TIMEZONE
# 1 = using JS_DATE_FORMAT and local user time (via moment.js)
# 2 = using a string like “2 days ago”
#
# Your theme must support it, bootstrap and bootstrap3 already do.
# DATE_FANCINESS = 0

# While Nikola can select a sensible locale for each language,
# sometimes explicit control can come handy.
# In this file we express locales in the string form that
# python's locales will accept in your OS, by example
# "en_US.utf8" in Unix-like OS, "English_United States" in Windows.
# LOCALES = dict mapping language --> explicit locale for the languages
# in TRANSLATIONS. You can omit one or more keys.
# LOCALE_FALLBACK = locale to use when an explicit locale is unavailable
# LOCALE_DEFAULT = locale to use for languages not mentioned in LOCALES; if
# not set the default Nikola mapping is used.

# LOCALES = {}
# LOCALE_FALLBACK = None
# LOCALE_DEFAULT = None

# One or more folders containing files to be copied as-is into the output.
# The format is a dictionary of {source: relative destination}.
# Default is:
# FILES_FOLDERS = {'files': ''}
# Which means copy 'files' into 'output'

# One or more folders containing code listings to be processed and published on
# the site. The format is a dictionary of {source: relative destination}.
# Default is:
# LISTINGS_FOLDERS = {'listings': 'listings'}
# Which means process listings from 'listings' into 'output/listings'

# A mapping of languages to file-extensions that represent that language.
# Feel free to add or delete extensions to any list, but don't add any new
# compilers unless you write the interface for it yourself.
#
# 'rest' is reStructuredText
# 'markdown' is MarkDown
# 'html' assumes the file is HTML and just copies it
COMPILERS = {
    "rest": ('.rst', '.txt'),
    "markdown": ('.md', '.mdown', '.markdown'),
    "textile": ('.textile',),
    "txt2tags": ('.t2t',),
    "bbcode": ('.bb',),
    "wiki": ('.wiki',),
    "ipynb": ('.ipynb',),
    "html": ('.html', '.htm'),
    # PHP files are rendered the usual way (i.e. with the full templates).
    # The resulting files have .php extensions, making it possible to run
    # them without reconfiguring your server to recognize them.
    "php": ('.php',),
    # Pandoc detects the input from the source filename
    # but is disabled by default as it would conflict
    # with many of the others.
    "docbookmanpage": ('.xml',),
}

# Create by default posts in one file format?
# Set to False for two-file posts, with separate metadata.
# ONE_FILE_POSTS = True

# Use date-based path when creating posts?
# Can be enabled on a per-post basis with `nikola new_post -d`.
# The setting is ignored when creating pages (`-d` still works).
NEW_POST_DATE_PATH = True

# What format to use when creating posts with date paths?
# Default is '%Y/%m/%d', other possibilities include '%Y' or '%Y/%m'.
NEW_POST_DATE_PATH_FORMAT = '%Y/%m'

# If this is set to True, the DEFAULT_LANG version will be displayed for
# untranslated posts.
# If this is set to False, then posts that are not translated to a language
# LANG will not be visible at all in the pages in that language.
# Formerly known as HIDE_UNTRANSLATED_POSTS (inverse)
# SHOW_UNTRANSLATED_POSTS = True

# Nikola supports logo display.  If you have one, you can put the URL here.
# Final output is <img src="LOGO_URL" id="logo" alt="BLOG_TITLE">.
# The URL may be relative to the site root.
# LOGO_URL = ''

# If you want to hide the title of your website (for example, if your logo
# already contains the text), set this to False.
SHOW_BLOG_TITLE = False

# Writes tag cloud data in form of tag_cloud_data.json.
# Warning: this option will change its default value to False in v8!
WRITE_TAG_CLOUD = True

# Generate pages for each section. The site must have at least two sections
# for this option to take effect. It wouldn't build for just one section.
POSTS_SECTIONS = True

# Setting this to False generates a list page instead of an index. Indexes
# are the default and will apply GENERATE_ATOM if set.
# POSTS_SECTIONS_ARE_INDEXES = True

# Final locations are:
# output / TRANSLATION[lang] / SECTION_PATH / SECTION_NAME / index.html (list of posts for a section)
# output / TRANSLATION[lang] / SECTION_PATH / SECTION_NAME / rss.xml (RSS feed for a section)
# (translatable)
# SECTION_PATH = ""

# Each post and section page will have an associated color that can be used
# to style them with a recognizable color detail across your site. A color
# is assigned to  each section based on shifting the hue of your THEME_COLOR
# at least 7.5 % while leaving the lightness and saturation untouched in the
# HUSL colorspace. You can overwrite colors by assigning them colors in HEX.
# POSTS_SECTION_COLORS = {
#     DEFAULT_LANG: {
#         'posts':  '#49b11bf',
#         'reviews':   '#ffe200',
#     },
# }

# Associate a description with a section. For use in meta description on
# section index pages or elsewhere in themes.
# POSTS_SECTION_DESCRIPTIONS = {
#     DEFAULT_LANG: {
#         'how-to': 'Learn how-to things properly with these amazing tutorials.',
#     },
# }

# Sections are determined by their output directory as set in POSTS by default,
# but can alternatively be determined from file metadata instead.
# POSTS_SECTION_FROM_META = False

# Names are determined from the output directory name automatically or the
# metadata label. Unless overwritten below, names will use title cased and
# hyphens replaced by spaces.
# POSTS_SECTION_NAME = {
#    DEFAULT_LANG: {
#        'posts': 'Blog Posts',
#        'uncategorized': 'Odds and Ends',
#    },
# }

# Titles for per-section index pages. Can be either one string where "{name}"
# is substituted or the POSTS_SECTION_NAME, or a dict of sections. Note
# that the INDEX_PAGES option is also applied to section page titles.
# POSTS_SECTION_TITLE = {
#     DEFAULT_LANG: {
#         'how-to': 'How-to and Tutorials',
#     },
# }

# Paths for different autogenerated bits. These are combined with the
# translation paths.

# Final locations are:
# output / TRANSLATION[lang] / TAG_PATH / index.html (list of tags)
# output / TRANSLATION[lang] / TAG_PATH / tag.html (list of posts for a tag)
# output / TRANSLATION[lang] / TAG_PATH / tag.xml (RSS feed for a tag)
# (translatable)
TAG_PATH = "blog/categories"

# By default, the list of tags is stored in
#     output / TRANSLATION[lang] / TAG_PATH / index.html
# (see explanation for TAG_PATH). This location can be changed to
#     output / TRANSLATION[lang] / TAGS_INDEX_PATH
# with an arbitrary relative path TAGS_INDEX_PATH.
# (translatable)
# TAGS_INDEX_PATH = "tags.html"

# If TAG_PAGES_ARE_INDEXES is set to True, each tag's page will contain
# the posts themselves. If set to False, it will be just a list of links.
# TAG_PAGES_ARE_INDEXES = False

# Set descriptions for tag pages to make them more interesting. The
# default is no description. The value is used in the meta description
# and displayed underneath the tag list or index page’s title.
# TAG_PAGES_DESCRIPTIONS = {
#    DEFAULT_LANG: {
#        "blogging": "Meta-blog posts about blogging about blogging.",
#        "open source": "My contributions to my many, varied, ever-changing, and eternal libre software projects."
#    },
# }

# Set special titles for tag pages. The default is "Posts about TAG".
# TAG_PAGES_TITLES = {
#    DEFAULT_LANG: {
#        "blogging": "Meta-posts about blogging",
#        "open source": "Posts about open source software"
#    },
# }

# If you do not want to display a tag publicly, you can mark it as hidden.
# The tag will not be displayed on the tag list page, the tag cloud and posts.
# Tag pages will still be generated.
HIDDEN_TAGS = ['mathjax']

# Only include tags on the tag list/overview page if there are at least
# TAGLIST_MINIMUM_POSTS number of posts or more with every tag. Every tag
# page is still generated, linked from posts, and included in the sitemap.
# However, more obscure tags can be hidden from the tag index page.
# TAGLIST_MINIMUM_POSTS = 1

# Final locations are:
# output / TRANSLATION[lang] / CATEGORY_PATH / index.html (list of categories)
# output / TRANSLATION[lang] / CATEGORY_PATH / CATEGORY_PREFIX category.html (list of posts for a category)
# output / TRANSLATION[lang] / CATEGORY_PATH / CATEGORY_PREFIX category.xml (RSS feed for a category)
# (translatable)
# CATEGORY_PATH = "categories"
# CATEGORY_PREFIX = "cat_"

# By default, the list of categories is stored in
#     output / TRANSLATION[lang] / CATEGORY_PATH / index.html
# (see explanation for CATEGORY_PATH). This location can be changed to
#     output / TRANSLATION[lang] / CATEGORIES_INDEX_PATH
# with an arbitrary relative path CATEGORIES_INDEX_PATH.
# (translatable)
# CATEGORIES_INDEX_PATH = "categories.html"

# If CATEGORY_ALLOW_HIERARCHIES is set to True, categories can be organized in
# hierarchies. For a post, the whole path in the hierarchy must be specified,
# using a forward slash ('/') to separate paths. Use a backslash ('\') to escape
# a forward slash or a backslash (i.e. '\//\\' is a path specifying the
# subcategory called '\' of the top-level category called '/').
CATEGORY_ALLOW_HIERARCHIES = False
# If CATEGORY_OUTPUT_FLAT_HIERARCHY is set to True, the output written to output
# contains only the name of the leaf category and not the whole path.
CATEGORY_OUTPUT_FLAT_HIERARCHY = False

# If CATEGORY_PAGES_ARE_INDEXES is set to True, each category's page will contain
# the posts themselves. If set to False, it will be just a list of links.
# CATEGORY_PAGES_ARE_INDEXES = False

# Set descriptions for category pages to make them more interesting. The
# default is no description. The value is used in the meta description
# and displayed underneath the category list or index page’s title.
# CATEGORY_PAGES_DESCRIPTIONS = {
#    DEFAULT_LANG: {
#        "blogging": "Meta-blog posts about blogging about blogging.",
#        "open source": "My contributions to my many, varied, ever-changing, and eternal libre software projects."
#    },
# }

# Set special titles for category pages. The default is "Posts about CATEGORY".
# CATEGORY_PAGES_TITLES = {
#    DEFAULT_LANG: {
#        "blogging": "Meta-posts about blogging",
#        "open source": "Posts about open source software"
#    },
# }

# If you do not want to display a category publicly, you can mark it as hidden.
# The category will not be displayed on the category list page.
# Category pages will still be generated.
HIDDEN_CATEGORIES = []

# If ENABLE_AUTHOR_PAGES is set to True and there is more than one
# author, author pages are generated.
# ENABLE_AUTHOR_PAGES = True

# Path to author pages. Final locations are:
# output / TRANSLATION[lang] / AUTHOR_PATH / index.html (list of authors)
# output / TRANSLATION[lang] / AUTHOR_PATH / author.html (list of posts by an author)
# output / TRANSLATION[lang] / AUTHOR_PATH / author.xml (RSS feed for an author)
# (translatable)
AUTHOR_PATH = "blog/authors"

# If AUTHOR_PAGES_ARE_INDEXES is set to True, each author's page will contain
# the posts themselves. If set to False, it will be just a list of links.
# AUTHOR_PAGES_ARE_INDEXES = False

# Set descriptions for author pages to make them more interesting. The
# default is no description. The value is used in the meta description
# and displayed underneath the author list or index page’s title.
# AUTHOR_PAGES_DESCRIPTIONS = {
#    DEFAULT_LANG: {
#        "Juanjo Conti": "Python coder and writer.",
#        "Roberto Alsina": "Nikola father."
#    },
# }


# If you do not want to display an author publicly, you can mark it as hidden.
# The author will not be displayed on the author list page and posts.
# Tag pages will still be generated.
HIDDEN_AUTHORS = ['Guest']

# Final location for the main blog page and sibling paginated pages is
# output / TRANSLATION[lang] / INDEX_PATH / index-*.html
# (translatable)
INDEX_PATH = "blog"

# Optional HTML that displayed on “main” blog index.html files.
# May be used for a greeting. (translatable)
FRONT_INDEX_HEADER = {
    DEFAULT_LANG: ''
}

# Create per-month archives instead of per-year
# CREATE_MONTHLY_ARCHIVE = False
# Create one large archive instead of per-year
# CREATE_SINGLE_ARCHIVE = False
# Create year, month, and day archives each with a (long) list of posts
# (overrides both CREATE_MONTHLY_ARCHIVE and CREATE_SINGLE_ARCHIVE)
# CREATE_FULL_ARCHIVES = False
# If monthly archives or full archives are created, adds also one archive per day
# CREATE_DAILY_ARCHIVE = False
# Create previous, up, next navigation links for archives
# CREATE_ARCHIVE_NAVIGATION = False
# Final locations for the archives are:
# output / TRANSLATION[lang] / ARCHIVE_PATH / ARCHIVE_FILENAME
# output / TRANSLATION[lang] / ARCHIVE_PATH / YEAR / index.html
# output / TRANSLATION[lang] / ARCHIVE_PATH / YEAR / MONTH / index.html
# output / TRANSLATION[lang] / ARCHIVE_PATH / YEAR / MONTH / DAY / index.html
# ARCHIVE_PATH = ""
# ARCHIVE_FILENAME = "archive.html"

# If ARCHIVES_ARE_INDEXES is set to True, each archive page which contains a list
# of posts will contain the posts themselves. If set to False, it will be just a
# list of links.
# ARCHIVES_ARE_INDEXES = False

# URLs to other posts/pages can take 3 forms:
# rel_path: a relative URL to the current page/post (default)
# full_path: a URL with the full path from the root
# absolute: a complete URL (that includes the SITE_URL)
# URL_TYPE = 'rel_path'

# If USE_BASE_TAG is True, then all HTML files will include
# something like <base href=http://foo.var.com/baz/bat> to help
# the browser resolve relative links.
# Most people don’t need this tag; major websites don’t use it. Use
# only if you know what you’re doing. If this is True, your website
# will not be fully usable by manually opening .html files in your web
# browser (`nikola serve` or `nikola auto` is mandatory). Also, if you
# have mirrors of your site, they will point to SITE_URL everywhere.
USE_BASE_TAG = False

# Final location for the blog main RSS feed is:
# output / TRANSLATION[lang] / RSS_PATH / rss.xml
# (translatable)
# RSS_PATH = ""

# Slug the Tag URL. Easier for users to type, special characters are
# often removed or replaced as well.
# SLUG_TAG_PATH = True

# Slug the Author URL. Easier for users to type, special characters are
# often removed or replaced as well.
# SLUG_AUTHOR_PATH = True

# A list of redirection tuples, [("foo/from.html", "/bar/to.html")].
#
# A HTML file will be created in output/foo/from.html that redirects
# to the "/bar/to.html" URL. notice that the "from" side MUST be a
# relative URL.
#
# If you don't need any of these, just set to []
REDIRECTIONS = [ \
    ["2009/12/version-0-2-released/index.html", "/blog/2009/12/version-0-2-released"], \
    ["2009/12/version-0-3-released/index.html", "/blog/2009/12/version-0-3-released"], \
    ["2010/01/mailing-list-irc/index.html", "/blog/2010/01/mailing-list-irc"], \
    ["2010/01/version-0-4-1-released/index.html", "/blog/2010/01/version-0-4-1-released"], \
    ["2010/01/version-0-4-released/index.html", "/blog/2010/01/version-0-4-released"], \
    ["2010/02/version-0-4-2-released/index.html", "/blog/2010/02/version-0-4-2-released"], \
    ["2010/03/google-powermeter/index.html", "/blog/2010/03/google-powermeter"], \
    ["2010/03/upgrading-to-0-5-1/index.html", "/blog/2010/03/upgrading-to-0-5-1"], \
    ["2010/03/version-0-5-1-released/index.html", "/blog/2010/03/version-0-5-1-released"], \
    ["2010/03/version-0-5-2-released/index.html", "/blog/2010/03/version-0-5-2-released"], \
    ["2010/03/version-0-5-3-released/index.html", "/blog/2010/03/version-0-5-3-released"], \
    ["2010/03/version-0-5-4-released/index.html", "/blog/2010/03/version-0-5-4-released"], \
    ["2010/04/help-wanted-rpm-packaging/index.html", "/blog/2010/04/help-wanted-rpm-packaging"], \
    ["2010/04/mind-control-mqtt/index.html", "/blog/2010/04/mind-control-mqtt"], \
    ["2010/04/oggcamp/index.html", "/blog/2010/04/oggcamp"], \
    ["2010/05/fedora-packages-available/index.html", "/blog/2010/05/fedora-packages-available"], \
    ["2010/05/gentoo-ebuilds-available/index.html", "/blog/2010/05/gentoo-ebuilds-available"], \
    ["2010/05/mosquitto-org/index.html", "/blog/2010/05/mosquitto-org"], \
    ["2010/05/mqtt-push-on-android/index.html", "/blog/2010/05/mqtt-push-on-android"], \
    ["2010/05/mqtt-wiki/index.html", "/blog/2010/05/mqtt-wiki"], \
    ["2010/05/version-0-6-1-released/index.html", "/blog/2010/05/version-0-6-1-released"], \
    ["2010/05/version-0-6-released/index.html", "/blog/2010/05/version-0-6-released"], \
    ["2010/06/automation-has-the-oven-warmed-up-yet/index.html", "/blog/2010/06/automation-has-the-oven-warmed-up-yet"], \
    ["2010/06/google-powermeter-step-by-step/index.html", "/blog/2010/06/google-powermeter-step-by-step"], \
    ["2010/06/mosquitto-0-7rc1/index.html", "/blog/2010/06/mosquitto-0-7rc1"], \
    ["2010/06/version-0-7-released/index.html", "/blog/2010/06/version-0-7-released"], \
    ["2010/07/mosquitto-on-opensuse-11-3/index.html", "/blog/2010/07/mosquitto-on-opensuse-11-3"], \
    ["2010/07/mqtt-client-library/index.html", "/blog/2010/07/mqtt-client-library"], \
    ["2010/08/compiling-mosquitto-on-mac-os-x/index.html", "/blog/2010/08/compiling-mosquitto-on-mac-os-x"], \
    ["2010/08/mosquitto-running-on-mac-os-x/index.html", "/blog/2010/08/mosquitto-running-on-mac-os-x"], \
    ["2010/08/mqtt-v3-1/index.html", "/blog/2010/08/mqtt-v3-1"], \
    ["2010/08/version-0-8-1-released/index.html", "/blog/2010/08/version-0-8-1-released"], \
    ["2010/08/version-0-8-2/index.html", "/blog/2010/08/version-0-8-2"], \
    ["2010/08/version-0-8-released/index.html", "/blog/2010/08/version-0-8-released"], \
    ["2010/09/debian-packages/index.html", "/blog/2010/09/debian-packages"], \
    ["2010/09/mqtt-with-php/index.html", "/blog/2010/09/mqtt-with-php"], \
    ["2010/10/man-page-translations/index.html", "/blog/2010/10/man-page-translations"], \
    ["2010/10/one-year-old/index.html", "/blog/2010/10/one-year-old"], \
    ["2010/10/version-0-8-3-released/index.html", "/blog/2010/10/version-0-8-3-released"], \
    ["2010/11/distro-packaging/index.html", "/blog/2010/11/distro-packaging"], \
    ["2010/11/mosquitto-0-9test2/index.html", "/blog/2010/11/mosquitto-0-9test2"], \
    ["2010/11/version-0-9-released/index.html", "/blog/2010/11/version-0-9-released"], \
    ["2010/12/version-0-9-1-released/index.html", "/blog/2010/12/version-0-9-1-released"], \
    ["2011/01/mosquitto-for-slackware/index.html", "/blog/2011/01/mosquitto-for-slackware"], \
    ["2011/01/mqtt-news/index.html", "/blog/2011/01/mqtt-news"], \
    ["2011/02/lightweight-messaging-and-linux/index.html", "/blog/2011/02/lightweight-messaging-and-linux"], \
    ["2011/02/mosquitto-on-maemo/index.html", "/blog/2011/02/mosquitto-on-maemo"], \
    ["2011/02/mqtt-on-android/index.html", "/blog/2011/02/mqtt-on-android"], \
    ["2011/02/version-0-9-2-released/index.html", "/blog/2011/02/version-0-9-2-released"], \
    ["2011/03/api-documentation/index.html", "/blog/2011/03/api-documentation"], \
    ["2011/03/mosquitto-in-mac-homebrew/index.html", "/blog/2011/03/mosquitto-in-mac-homebrew"], \
    ["2011/03/version-0-9-3-released/index.html", "/blog/2011/03/version-0-9-3-released"], \
    ["2011/04/version-0-10-released/index.html", "/blog/2011/04/version-0-10-released"], \
    ["2011/05/mqtt-ontology/index.html", "/blog/2011/05/mqtt-ontology"], \
    ["2011/05/version-0-10-1-released/index.html", "/blog/2011/05/version-0-10-1-released"], \
    ["2011/06/nanode-a-cheap-networked-arduino-clone/index.html", "/blog/2011/06/nanode-a-cheap-networked-arduino-clone"], \
    ["2011/06/version-0-10-2-released/index.html", "/blog/2011/06/version-0-10-2-released"], \
    ["2011/06/version-0-11-1-released/index.html", "/blog/2011/06/version-0-11-1-released"], \
    ["2011/06/version-0-11-2-released/index.html", "/blog/2011/06/version-0-11-2-released"], \
    ["2011/06/version-0-11-released/index.html", "/blog/2011/06/version-0-11-released"], \
    ["2011/07/debian-and-ubuntu-packaging/index.html", "/blog/2011/07/debian-and-ubuntu-packaging"], \
    ["2011/07/lua-mqtt-client/index.html", "/blog/2011/07/lua-mqtt-client"], \
    ["2011/07/mosquitto-on-qnx/index.html", "/blog/2011/07/mosquitto-on-qnx"], \
    ["2011/07/version-0-11-3-released/index.html", "/blog/2011/07/version-0-11-3-released"], \
    ["2011/07/version-0-12-released/index.html", "/blog/2011/07/version-0-12-released"], \
    ["2011/07/wireshark-mqtt-decoder/index.html", "/blog/2011/07/wireshark-mqtt-decoder"], \
    ["2011/08/arch-linux-package/index.html", "/blog/2011/08/arch-linux-package"], \
    ["2011/08/facebook-using-mqtt/index.html", "/blog/2011/08/facebook-using-mqtt"], \
    ["2011/08/mosquitto-on-openwrt/index.html", "/blog/2011/08/mosquitto-on-openwrt"], \
    ["2011/08/mqtt-standardisation/index.html", "/blog/2011/08/mqtt-standardisation"], \
    ["2011/09/version-0-13-released/index.html", "/blog/2011/09/version-0-13-released"], \
    ["2011/10/mqtt-power-usage-on-android/index.html", "/blog/2011/10/mqtt-power-usage-on-android"], \
    ["2011/10/two/index.html", "/blog/2011/10/two"], \
    ["2011/11/android-mqtt-example-project/index.html", "/blog/2011/11/android-mqtt-example-project"], \
    ["2011/11/ibm-java-and-c-clients-to-be-open-source/index.html", "/blog/2011/11/ibm-java-and-c-clients-to-be-open-source"], \
    ["2011/11/new-linux-repositories/index.html", "/blog/2011/11/new-linux-repositories"], \
    ["2011/11/version-0-14-1-released/index.html", "/blog/2011/11/version-0-14-1-released"], \
    ["2011/11/version-0-14-2-released/index.html", "/blog/2011/11/version-0-14-2-released"], \
    ["2011/11/version-0-14-released/index.html", "/blog/2011/11/version-0-14-released"], \
    ["2011/12/mqtt-on-nanode/index.html", "/blog/2011/12/mqtt-on-nanode"], \
    ["2011/12/version-0-14-3-released/index.html", "/blog/2011/12/version-0-14-3-released"], \
    ["2012/01/challenge-web-based-mqtt-graphing/index.html", "/blog/2012/01/challenge-web-based-mqtt-graphing"], \
    ["2012/01/do-you-use-mqtt/index.html", "/blog/2012/01/do-you-use-mqtt"], \
    ["2012/01/mosquitto-test-server/index.html", "/blog/2012/01/mosquitto-test-server"], \
    ["2012/01/version-0-14-4-released/index.html", "/blog/2012/01/version-0-14-4-released"], \
    ["2012/02/mqtt2pachube/index.html", "/blog/2012/02/mqtt2pachube"], \
    ["2012/02/version-0-15-released/index.html", "/blog/2012/02/version-0-15-released"], \
    ["2012/03/quick-start-guide-for-mqtt-with-pachube/index.html", "/blog/2012/03/quick-start-guide-for-mqtt-with-pachube"], \
    ["2012/03/upcoming-incompatible-library-changes/index.html", "/blog/2012/03/upcoming-incompatible-library-changes"], \
    ["2012/05/python-client-module-available-for-testing/index.html", "/blog/2012/05/python-client-module-available-for-testing"], \
    ["2012/06/ipv6-on-test-server/index.html", "/blog/2012/06/ipv6-on-test-server"], \
    ["2012/06/ssl-support-on-test-server/index.html", "/blog/2012/06/ssl-support-on-test-server"], \
    ["2012/07/upcoming-release/index.html", "/blog/2012/07/upcoming-release"], \
    ["2012/08/baby/index.html", "/blog/2012/08/baby"], \
    ["2012/08/bugfix-coming-soon/index.html", "/blog/2012/08/bugfix-coming-soon"], \
    ["2012/08/version-1-0-1-released/index.html", "/blog/2012/08/version-1-0-1-released"], \
    ["2012/08/version-1-0-2-released/index.html", "/blog/2012/08/version-1-0-2-released"], \
    ["2012/08/version-1-0-released/index.html", "/blog/2012/08/version-1-0-released"], \
    ["2012/09/updating-password-files/index.html", "/blog/2012/09/updating-password-files"], \
    ["2012/09/version-1-0-3-released/index.html", "/blog/2012/09/version-1-0-3-released"], \
    ["2012/10/version-1-0-4-released/index.html", "/blog/2012/10/version-1-0-4-released"], \
    ["2012/11/making-mosquitto-packages-for-debian-yourself/index.html", "/blog/2012/11/making-mosquitto-packages-for-debian-yourself"], \
    ["2012/11/version-1-0-5-released/index.html", "/blog/2012/11/version-1-0-5-released"], \
    ["2012/12/libmosquitto-go-bindings/index.html", "/blog/2012/12/libmosquitto-go-bindings"], \
    ["2012/12/version-1-1-released/index.html", "/blog/2012/12/version-1-1-released"], \
    ["2013/01/mosquitto-debian-repository/index.html", "/blog/2013/01/mosquitto-debian-repository"], \
    ["2013/01/version-1-1-1-released/index.html", "/blog/2013/01/version-1-1-1-released"], \
    ["2013/01/version-1-1-2-released/index.html", "/blog/2013/01/version-1-1-2-released"], \
    ["2013/02/mqtt-standardisation-oasis-call-for-participation/index.html", "/blog/2013/02/mqtt-standardisation-oasis-call-for-participation"], \
    ["2013/02/version-1-1-3-released/index.html", "/blog/2013/02/version-1-1-3-released"], \
    ["2013/04/some-interesting-mqtt-things/index.html", "/blog/2013/04/some-interesting-mqtt-things"], \
    ["2013/05/mosquitto-javascript-client-deprecated/index.html", "/blog/2013/05/mosquitto-javascript-client-deprecated"], \
    ["2013/07/authentication-plugins/index.html", "/blog/2013/07/authentication-plugins"], \
    ["2013/07/version-1-2-near-complete/index.html", "/blog/2013/07/version-1-2-near-complete"], \
    ["2013/08/mosquitto-on-fedora/index.html", "/blog/2013/08/mosquitto-on-fedora"], \
    ["2013/08/mqtt-watchdir/index.html", "/blog/2013/08/mqtt-watchdir"], \
    ["2013/08/version-1-2-released/index.html", "/blog/2013/08/version-1-2-released"], \
    ["2013/09/version-1-2-1-released/index.html", "/blog/2013/09/version-1-2-1-released"], \
    ["2013/10/version-1-2-2-released/index.html", "/blog/2013/10/version-1-2-2-released"], \
    ["2013/12/paho-mqtt-python-client/index.html", "/blog/2013/12/paho-mqtt-python-client"], \
    ["2013/12/version-1-2-3-released/index.html", "/blog/2013/12/version-1-2-3-released"], \
    ["2014/03/version-1-3-1-released/index.html", "/blog/2014/03/version-1-3-1-released"], \
    ["2014/03/version-1-3-released/index.html", "/blog/2014/03/version-1-3-released"], \
    ["2014/05/new-arrival/index.html", "/blog/2014/05/new-arrival"], \
    ["2014/07/version-1-3-2-released/index.html", "/blog/2014/07/version-1-3-2-released"], \
    ["2014/08/version-1-3-3-released/index.html", "/blog/2014/08/version-1-3-3-released"], \
    ["2014/08/version-1-3-4-released/index.html", "/blog/2014/08/version-1-3-4-released"], \
    ["2014/10/mosquitto-and-poodle/index.html", "/blog/2014/10/mosquitto-and-poodle"], \
    ["2014/10/unintended-change-of-behaviour-in-1-3-4/index.html", "/blog/2014/10/unintended-change-of-behaviour-in-1-3-4"], \
    ["2014/10/version-1-3-5-released/index.html", "/blog/2014/10/version-1-3-5-released"], \
    ["2015/01/seeking-sponsorship/index.html", "/blog/2015/01/seeking-sponsorship"], \
    ["2015/02/version-1-4-released/index.html", "/blog/2015/02/version-1-4-released"], \
    ["2015/04/version-1-4-1-released/index.html", "/blog/2015/04/version-1-4-1-released"], \
    ["2015/05/mosquitto-and-current-unreleased-libwebsockets-branch/index.html", "/blog/2015/05/mosquitto-and-current-unreleased-libwebsockets-branch"], \
    ["2015/05/version-1-4-2-released/index.html", "/blog/2015/05/version-1-4-2-released"], \
    ["2015/08/version-1-4-3-released/index.html", "/blog/2015/08/version-1-4-3-released"], \
    ["2015/09/version-1-4-4-released/index.html", "/blog/2015/09/version-1-4-4-released"], \
    ["2015/11/version-1-4-5-released/index.html", "/blog/2015/11/version-1-4-5-released"], \
    ["2015/12/using-lets-encrypt-certificates-with-mosquitto/index.html", "/blog/2015/12/using-lets-encrypt-certificates-with-mosquitto"], \
    ["2015/12/version-1-4-7-released/index.html", "/blog/2015/12/version-1-4-7-released"], \
    ["2016/01/test6-mosquitto-org/index.html", "/blog/2016/01/test6-mosquitto-org"], \
    ["2016/02/version-1-4-8-released/index.html", "/blog/2016/02/version-1-4-8-released"], \
    ["2016/03/logo-contest-results-for-shortlisting/index.html", "/blog/2016/03/logo-contest-results-for-shortlisting"], \
    ["2016/03/logo-contest/index.html", "/blog/2016/03/logo-contest"], \
    ["2016/03/repository-moved-to-github/index.html", "/blog/2016/03/repository-moved-to-github"], \
    ["2016/05/stickers/index.html", "/blog/2016/05/stickers"], \
    ["2016/06/version-1-4-9-released/index.html", "/blog/2016/06/version-1-4-9-released"], \
    ["2016/08/mqtt-v5-draft-features/index.html", "/blog/2016/08/mqtt-v5-draft-features"], \
    ["2016/08/version-1-4-10-released/index.html", "/blog/2016/08/version-1-4-10-released"], \
    ["2016/12/pre-christmas-update/index.html", "/blog/2016/12/pre-christmas-update"], \
    ["2017/02/version-1-4-11-released/index.html", "/blog/2017/02/version-1-4-11-released"], \
    ["2017/03/for-the-final-time/index.html", "/blog/2017/03/for-the-final-time"], \
    ["2017/05/security-advisory-cve-2017-7650/index.html", "/blog/2017/05/security-advisory-cve-2017-7650"], \
    ["2017/06/citing-eclipse-mosquitto/index.html", "/blog/2017/06/citing-eclipse-mosquitto"], \
    ["2017/06/security-advisory-cve-2017-9868/index.html", "/blog/2017/06/security-advisory-cve-2017-9868"], \
    ["2017/07/version-1-4-13-released/index.html", "/blog/2017/07/version-1-4-13-released"], \
    ["2017/07/version-1-4-14-released/index.html", "/blog/2017/07/version-1-4-14-released"], \
    ["2018/01/mosquitto-debian-repo-key-updated/index.html", "/blog/2018/01/mosquitto-debian-repo-key-updated"] \
    ]


## Presets of commands to execute to deploy. Can be anything, for
# example, you may use rsync:
# "rsync -rav --delete output/ joe@my.site:/srv/www/site"
# And then do a backup, or run `nikola ping` from the `ping`
# plugin (`nikola plugin -i ping`).  Or run `nikola check -l`.
# You may also want to use github_deploy (see below).
# You can define multiple presets and specify them as arguments
# to `nikola deploy`.  If no arguments are specified, a preset
# named `default` will be executed.  You can use as many presets
# in a `nikola deploy` command as you like.
# DEPLOY_COMMANDS = {
#     'default': [
#         "rsync -rav --delete output/ joe@my.site:/srv/www/site",
#     ]
# }

# github_deploy configuration
# For more details, read the manual:
# https://getnikola.com/handbook.html#deploying-to-github
# You will need to configure the deployment branch on GitHub.
GITHUB_SOURCE_BRANCH = 'src'
GITHUB_DEPLOY_BRANCH = 'master'

# The name of the remote where you wish to push to, using github_deploy.
GITHUB_REMOTE_NAME = 'origin'

# Whether or not github_deploy should commit to the source branch automatically
# before deploying.
GITHUB_COMMIT_SOURCE = True

# Where the output site should be located
# If you don't use an absolute path, it will be considered as relative
# to the location of conf.py
OUTPUT_FOLDER = '/home/mosqorg/site/mosquitto.org'

# where the "cache" of partial generated content should be located
# default: 'cache'
# CACHE_FOLDER = 'cache'

# Filters to apply to the output.
# A directory where the keys are either: a file extensions, or
# a tuple of file extensions.
#
# And the value is a list of commands to be applied in order.
#
# Each command must be either:
#
# A string containing a '%s' which will
# be replaced with a filename. The command *must* produce output
# in place.
#
# Or:
#
# A python callable, which will be called with the filename as
# argument.
#
# By default, only .php files uses filters to inject PHP into
# Nikola’s templates. All other filters must be enabled through FILTERS.
#
# Many filters are shipped with Nikola. A list is available in the manual:
# <https://getnikola.com/handbook.html#post-processing-filters>
#
# from nikola import filters
# FILTERS = {
#    ".html": [filters.typogrify],
#    ".js": [filters.closure_compiler],
#    ".jpg": ["jpegoptim --strip-all -m75 -v %s"],
# }

# Executable for the "yui_compressor" filter (defaults to 'yui-compressor').
# YUI_COMPRESSOR_EXECUTABLE = 'yui-compressor'

# Executable for the "closure_compiler" filter (defaults to 'closure-compiler').
# CLOSURE_COMPILER_EXECUTABLE = 'closure-compiler'

# Executable for the "optipng" filter (defaults to 'optipng').
# OPTIPNG_EXECUTABLE = 'optipng'

# Executable for the "jpegoptim" filter (defaults to 'jpegoptim').
# JPEGOPTIM_EXECUTABLE = 'jpegoptim'

# Executable for the "html_tidy_withconfig", "html_tidy_nowrap",
# "html_tidy_wrap", "html_tidy_wrap_attr" and "html_tidy_mini" filters
# (defaults to 'tidy5').
# HTML_TIDY_EXECUTABLE = 'tidy5'



# Expert setting! Create a gzipped copy of each generated file. Cheap server-
# side optimization for very high traffic sites or low memory servers.
# GZIP_FILES = False
# File extensions that will be compressed
# GZIP_EXTENSIONS = ('.txt', '.htm', '.html', '.css', '.js', '.json', '.atom', '.xml')
# Use an external gzip command? None means no.
# Example: GZIP_COMMAND = "pigz -k {filename}"
# GZIP_COMMAND = None
# Make sure the server does not return a "Accept-Ranges: bytes" header for
# files compressed by this option! OR make sure that a ranged request does not
# return partial content of another representation for these resources. Do not
# use this feature if you do not understand what this means.

# Compiler to process LESS files.
# LESS_COMPILER = 'lessc'

# A list of options to pass to the LESS compiler.
# Final command is: LESS_COMPILER LESS_OPTIONS file.less
# LESS_OPTIONS = []

# Compiler to process Sass files.
# SASS_COMPILER = 'sass'

# A list of options to pass to the Sass compiler.
# Final command is: SASS_COMPILER SASS_OPTIONS file.s(a|c)ss
# SASS_OPTIONS = []

# #############################################################################
# Image Gallery Options
# #############################################################################

# One or more folders containing galleries. The format is a dictionary of
# {"source": "relative_destination"}, where galleries are looked for in
# "source/" and the results will be located in
# "OUTPUT_PATH/relative_destination/gallery_name"
# Default is:
# GALLERY_FOLDERS = {"galleries": "galleries"}
# More gallery options:
# THUMBNAIL_SIZE = 180
# MAX_IMAGE_SIZE = 1280
# USE_FILENAME_AS_TITLE = True
# EXTRA_IMAGE_EXTENSIONS = []
#
# If set to False, it will sort by filename instead. Defaults to True
# GALLERY_SORT_BY_DATE = True

# If set to True, EXIF data will be copied when an image is thumbnailed or
# resized. (See also EXIF_WHITELIST)
# PRESERVE_EXIF_DATA = False

# If you have enabled PRESERVE_EXIF_DATA, this option lets you choose EXIF
# fields you want to keep in images. (See also PRESERVE_EXIF_DATA)
#
# For a full list of field names, please see here:
# http://www.cipa.jp/std/documents/e/DC-008-2012_E.pdf
#
# This is a dictionary of lists. Each key in the dictionary is the
# name of a IDF, and each list item is a field you want to preserve.
# If you have a IDF with only a '*' item, *EVERY* item in it will be
# preserved. If you don't want to preserve anything in a IDF, remove it
# from the setting. By default, no EXIF information is kept.
# Setting the whitelist to anything other than {} implies
# PRESERVE_EXIF_DATA is set to True
# To preserve ALL EXIF data, set EXIF_WHITELIST to {"*": "*"}

# EXIF_WHITELIST = {}

# Some examples of EXIF_WHITELIST settings:

# Basic image information:
# EXIF_WHITELIST['0th'] = [
#    "Orientation",
#    "XResolution",
#    "YResolution",
# ]

# If you want to keep GPS data in the images:
# EXIF_WHITELIST['GPS'] = ["*"]

# Embedded thumbnail information:
# EXIF_WHITELIST['1st'] = ["*"]

# Folders containing images to be used in normal posts or pages.
# IMAGE_FOLDERS is a dictionary of the form {"source": "destination"},
# where "source" is the folder containing the images to be published, and
# "destination" is the folder under OUTPUT_PATH containing the images copied
# to the site. Thumbnail images will be created there as well.

# To reference the images in your posts, include a leading slash in the path.
# For example, if IMAGE_FOLDERS = {'images': 'images'}, write
#
#   .. image:: /images/tesla.jpg
#
# See the Nikola Handbook for details (in the “Embedding Images” and
# “Thumbnails” sections)

# Images will be scaled down according to IMAGE_THUMBNAIL_SIZE and MAX_IMAGE_SIZE
# options, but will have to be referenced manually to be visible on the site
# (the thumbnail has ``.thumbnail`` added before the file extension by default,
# but a different naming template can be configured with IMAGE_THUMBNAIL_FORMAT).

IMAGE_FOLDERS = {'images': 'images'}
# IMAGE_THUMBNAIL_SIZE = 400
# IMAGE_THUMBNAIL_FORMAT = '{name}.thumbnail{ext}'

# #############################################################################
# HTML fragments and diverse things that are used by the templates
# #############################################################################

# Data about post-per-page indexes.
# INDEXES_PAGES defaults to ' old posts, page %d' or ' page %d' (translated),
# depending on the value of INDEXES_PAGES_MAIN.
#
# (translatable) If the following is empty, defaults to BLOG_TITLE:
# INDEXES_TITLE = ""
#
# (translatable) If the following is empty, defaults to ' [old posts,] page %d' (see above):
# INDEXES_PAGES = ""
#
# If the following is True, INDEXES_PAGES is also displayed on the main (the
# newest) index page (index.html):
# INDEXES_PAGES_MAIN = False
#
# If the following is True, index-1.html has the oldest posts, index-2.html the
# second-oldest posts, etc., and index.html has the newest posts. This ensures
# that all posts on index-x.html will forever stay on that page, now matter how
# many new posts are added.
# If False, index-1.html has the second-newest posts, index-2.html the third-newest,
# and index-n.html the oldest posts. When this is active, old posts can be moved
# to other index pages when new posts are added.
# INDEXES_STATIC = True
#
# (translatable) If PRETTY_URLS is set to True, this setting will be used to create
# prettier URLs for index pages, such as page/2/index.html instead of index-2.html.
# Valid values for this settings are:
#   * False,
#   * a list or tuple, specifying the path to be generated,
#   * a dictionary mapping languages to lists or tuples.
# Every list or tuple must consist of strings which are used to combine the path;
# for example:
#     ['page', '{number}', '{index_file}']
# The replacements
#     {number}     --> (logical) page number;
#     {old_number} --> the page number inserted into index-n.html before (zero for
#                      the main page);
#     {index_file} --> value of option INDEX_FILE
# are made.
# Note that in case INDEXES_PAGES_MAIN is set to True, a redirection will be created
# for the full URL with the page number of the main page to the normal (shorter) main
# page URL.
# INDEXES_PRETTY_PAGE_URL = False
#
# If the following is true, a page range navigation will be inserted to indices.
# Please note that this will undo the effect of INDEXES_STATIC, as all index pages
# must be recreated whenever the number of pages changes.
# SHOW_INDEX_PAGE_NAVIGATION = False

# If the following is True, a meta name="generator" tag is added to pages. The
# generator tag is used to specify the software used to generate the page
# (it promotes Nikola).
# META_GENERATOR_TAG = True

# Color scheme to be used for code blocks. If your theme provides
# "assets/css/code.css" this is ignored. Leave empty to disable.
# Can be any of:
# algol, algol_nu, autumn, borland, bw, colorful, default, emacs, friendly,
# fruity, igor, lovelace, manni, monokai, murphy, native, paraiso-dark,
# paraiso-light, pastie, perldoc, rrt, tango, trac, vim, vs, xcode
# This list MAY be incomplete since pygments adds styles every now and then.
# Check with list(pygments.styles.get_all_styles()) in an interpreter.
# CODE_COLOR_SCHEME = 'default'

# FAVICONS contains (name, file, size) tuples.
# Used to create favicon link like this:
# <link rel="name" href="file" sizes="size"/>
FAVICONS = (
    ("icon", "/favicon-16x16.png", "16x16"),
    ("icon", "/favicon-32x32.png", "32x32"),
 )

# Show teasers (instead of full posts) in indexes? Defaults to False.
# INDEX_TEASERS = False

# HTML fragments with the Read more... links.
# The following tags exist and are replaced for you:
# {link}                        A link to the full post page.
# {read_more}                   The string “Read more” in the current language.
# {reading_time}                An estimate of how long it will take to read the post.
# {remaining_reading_time}      An estimate of how long it will take to read the post, sans the teaser.
# {min_remaining_read}          The string “{remaining_reading_time} min remaining to read” in the current language.
# {paragraph_count}             The amount of paragraphs in the post.
# {remaining_paragraph_count}   The amount of paragraphs in the post, sans the teaser.
# {post_title}                  The title of the post.
# {{                            A literal { (U+007B LEFT CURLY BRACKET)
# }}                            A literal } (U+007D RIGHT CURLY BRACKET)

# 'Read more...' for the index page, if INDEX_TEASERS is True (translatable)
INDEX_READ_MORE_LINK = '<p class="more"><a href="{link}">{read_more}…</a></p>'
# 'Read more...' for the feeds, if FEED_TEASERS is True (translatable)
FEED_READ_MORE_LINK = '<p><a href="{link}">{read_more}…</a> ({min_remaining_read})</p>'

# Append a URL query to the FEED_READ_MORE_LINK in Atom and RSS feeds. Advanced
# option used for traffic source tracking.
# Minimum example for use with Piwik: "pk_campaign=feed"
# The following tags exist and are replaced for you:
# {feedRelUri}                  A relative link to the feed.
# {feedFormat}                  The name of the syndication format.
# Example using replacement for use with Google Analytics:
# "utm_source={feedRelUri}&utm_medium=nikola_feed&utm_campaign={feedFormat}_feed"
FEED_LINKS_APPEND_QUERY = False

# A HTML fragment describing the license, for the sidebar.
# (translatable)
LICENSE = ""
# I recommend using the Creative Commons' wizard:
# https://creativecommons.org/choose/
# LICENSE = """
# <a rel="license" href="https://creativecommons.org/licenses/by-nc-sa/4.0/">
# <img alt="Creative Commons License BY-NC-SA"
# style="border-width:0; margin-bottom:12px;"
# src="https://i.creativecommons.org/l/by-nc-sa/4.0/88x31.png"></a>"""

# A small copyright notice for the page footer (in HTML).
# (translatable)
CONTENT_FOOTER = 'Contents &copy; {date}         <a href="mailto:{email}">{author}</a> - Powered by         <a href="https://getnikola.com" rel="nofollow">Nikola</a>         {license}'

# Things that will be passed to CONTENT_FOOTER.format().  This is done
# for translatability, as dicts are not formattable.  Nikola will
# intelligently format the setting properly.
# The setting takes a dict. The keys are languages. The values are
# tuples of tuples of positional arguments and dicts of keyword arguments
# to format().  For example, {'en': (('Hello'), {'target': 'World'})}
# results in CONTENT_FOOTER['en'].format('Hello', target='World').
# WARNING: If you do not use multiple languages with CONTENT_FOOTER, this
#          still needs to be a dict of this format.  (it can be empty if you
#          do not need formatting)
# (translatable)
CONTENT_FOOTER_FORMATS = {
    DEFAULT_LANG: (
        (),
        {
            "email": BLOG_EMAIL,
            "author": BLOG_AUTHOR,
            "date": time.gmtime().tm_year,
            "license": LICENSE
        }
    )
}

# A simple copyright tag for inclusion in RSS feeds that works just
# like CONTENT_FOOTER and CONTENT_FOOTER_FORMATS
RSS_COPYRIGHT = 'Contents © {date} <a href="mailto:{email}">{author}</a> {license}'
RSS_COPYRIGHT_PLAIN = 'Contents © {date} {author} {license}'
RSS_COPYRIGHT_FORMATS = CONTENT_FOOTER_FORMATS

# To use comments, you can choose between different third party comment
# systems.  The following comment systems are supported by Nikola:
#   disqus, facebook, googleplus, intensedebate, isso, livefyre, muut
# You can leave this option blank to disable comments.
COMMENT_SYSTEM = ""
# And you also need to add your COMMENT_SYSTEM_ID which
# depends on what comment system you use. The default is
# "nikolademo" which is a test account for Disqus. More information
# is in the manual.
#COMMENT_SYSTEM_ID = "mosquitto"

# Enable annotations using annotateit.org?
# If set to False, you can still enable them for individual posts and pages
# setting the "annotations" metadata.
# If set to True, you can disable them for individual posts and pages using
# the "noannotations" metadata.
# ANNOTATIONS = False

# Create index.html for page folders?
# WARNING: if a page would conflict with the index file (usually
#          caused by setting slug to `index`), the PAGE_INDEX
#          will not be generated for that directory.
# PAGE_INDEX = False
# Enable comments on pages (i.e. not posts)?
# COMMENTS_IN_PAGES = False
# Enable comments on picture gallery pages?
# COMMENTS_IN_GALLERIES = False

# What file should be used for directory indexes?
# Defaults to index.html
# Common other alternatives: default.html for IIS, index.php
# INDEX_FILE = "index.html"

# If a link ends in /index.html,  drop the index.html part.
# http://mysite/foo/bar/index.html => http://mysite/foo/bar/
# (Uses the INDEX_FILE setting, so if that is, say, default.html,
# it will instead /foo/default.html => /foo)
# (Note: This was briefly STRIP_INDEX_HTML in v 5.4.3 and 5.4.4)
STRIP_INDEXES = True

# Should the sitemap list directories which only include other directories
# and no files.
# Default to True
# If this is False
# e.g. /2012 includes only /01, /02, /03, /04, ...: don't add it to the sitemap
# if /2012 includes any files (including index.html)... add it to the sitemap
# SITEMAP_INCLUDE_FILELESS_DIRS = True

# List of files relative to the server root (!) that will be asked to be excluded
# from indexing and other robotic spidering. * is supported. Will only be effective
# if SITE_URL points to server root. The list is used to exclude resources from
# /robots.txt and /sitemap.xml, and to inform search engines about /sitemapindex.xml.
# ROBOTS_EXCLUSIONS = ["/archive.html", "/category/*.html"]

# Instead of putting files in <slug>.html, put them in <slug>/index.html.
# No web server configuration is required. Also enables STRIP_INDEXES.
# This can be disabled on a per-page/post basis by adding
#    .. pretty_url: False
# to the metadata.
PRETTY_URLS = True

# If True, publish future dated posts right away instead of scheduling them.
# Defaults to False.
# FUTURE_IS_NOW = False

# If True, future dated posts are allowed in deployed output
# Only the individual posts are published/deployed; not in indexes/sitemap
# Generally, you want FUTURE_IS_NOW and DEPLOY_FUTURE to be the same value.
# DEPLOY_FUTURE = False
# If False, draft posts will not be deployed
# DEPLOY_DRAFTS = True

# Allows scheduling of posts using the rule specified here (new_post -s)
# Specify an iCal Recurrence Rule: http://www.kanzaki.com/docs/ical/rrule.html
# SCHEDULE_RULE = ''
# If True, use the scheduling rule to all posts by default
# SCHEDULE_ALL = False

# Do you want a add a Mathjax config file?
# MATHJAX_CONFIG = ""

# If you want support for the $.$ syntax (which may conflict with running
# text!), just use this config:
# MATHJAX_CONFIG = """
# <script type="text/x-mathjax-config">
# MathJax.Hub.Config({
#     tex2jax: {
#         inlineMath: [ ['$','$'], ["\\\(","\\\)"] ],
#         displayMath: [ ['$$','$$'], ["\\\[","\\\]"] ],
#         processEscapes: true
#     },
#     displayAlign: 'center', // Change this to 'left' if you want left-aligned equations.
#     "HTML-CSS": {
#         styles: {'.MathJax_Display': {"margin": 0}}
#     }
# });
# </script>
# """

# Want to use KaTeX instead of MathJax? While KaTeX may not support every
# feature yet, it's faster and the output looks better.
# USE_KATEX = False

# KaTeX auto-render settings. If you want support for the $.$ syntax (wihch may
# conflict with running text!), just use this config:
# KATEX_AUTO_RENDER = """
# delimiters: [
#     {left: "$$", right: "$$", display: true},
#     {left: "\\\[", right: "\\\]", display: true},
#     {left: "$", right: "$", display: false},
#     {left: "\\\(", right: "\\\)", display: false}
# ]
# """

# Do you want to customize the nbconversion of your IPython notebook?
# IPYNB_CONFIG = {}
# With the following example configuration you can use a custom jinja template
# called `toggle.tpl` which has to be located in your site/blog main folder:
# IPYNB_CONFIG = {'Exporter':{'template_file': 'toggle'}}

# What Markdown extensions to enable?
# You will also get gist, nikola and podcast because those are
# done in the code, hope you don't mind ;-)
# Note: most Nikola-specific extensions are done via the Nikola plugin system,
#       with the MarkdownExtension class and should not be added here.
# The default is ['fenced_code', 'codehilite']
#MARKDOWN_EXTENSIONS = ['fenced_code', 'codehilite', 'extra', 'toc']

MARKDOWN_EXTENSIONS = ['markdown.extensions.fenced_code', 'markdown.extensions.codehilite', 'markdown.extensions.extra', 'markdown.extensions.toc']

# Options to be passed to markdown extensions (See https://python-markdown.github.io/reference/)
# Default is {} (no config at all)
MARKDOWN_EXTENSION_CONFIGS = {
    DEFAULT_LANG: {
        'markdown.extensions.toc':{
            'toc_depth':2
        }
    }
}


# Extra options to pass to the pandoc command.
# by default, it's empty, is a list of strings, for example
# ['-F', 'pandoc-citeproc', '--bibliography=/Users/foo/references.bib']
# Pandoc does not demote headers by default.  To enable this, you can use, for example
# ['--base-header-level=2']
# PANDOC_OPTIONS = []

# Social buttons. This is sample code for AddThis (which was the default for a
# long time). Insert anything you want here, or even make it empty (which is
# the default right now)
# (translatable)
# SOCIAL_BUTTONS_CODE = """
# <!-- Social buttons -->
# <div id="addthisbox" class="addthis_toolbox addthis_peekaboo_style addthis_default_style addthis_label_style addthis_32x32_style">
# <a class="addthis_button_more">Share</a>
# <ul><li><a class="addthis_button_facebook"></a>
# <li><a class="addthis_button_google_plusone_share"></a>
# <li><a class="addthis_button_linkedin"></a>
# <li><a class="addthis_button_twitter"></a>
# </ul>
# </div>
# <script src="https://s7.addthis.com/js/300/addthis_widget.js#pubid=ra-4f7088a56bb93798"></script>
# <!-- End of social buttons -->
# """

# Show link to source for the posts?
# Formerly known as HIDE_SOURCELINK (inverse)
SHOW_SOURCELINK = False
# Copy the source files for your pages?
# Setting it to False implies SHOW_SOURCELINK = False
COPY_SOURCES = False

# Modify the number of Post per Index Page
# Defaults to 10
# INDEX_DISPLAY_POST_COUNT = 10

# By default, Nikola generates RSS files for the website and for tags, and
# links to it.  Set this to False to disable everything RSS-related.
# GENERATE_RSS = True

# By default, Nikola does not generates Atom files for indexes and links to
# them. Generate Atom for tags by setting TAG_PAGES_ARE_INDEXES to True.
# Atom feeds are built based on INDEX_DISPLAY_POST_COUNT and not FEED_LENGTH
# Switch between plain-text summaries and full HTML content using the
# FEED_TEASER option. FEED_LINKS_APPEND_QUERY is also respected. Atom feeds
# are generated even for old indexes and have pagination link relations
# between each other. Old Atom feeds with no changes are marked as archived.
# GENERATE_ATOM = False

# Only include teasers in Atom and RSS feeds. Disabling include the full
# content. Defaults to True.
# FEED_TEASERS = True

# Strip HTML from Atom and RSS feed summaries and content. Defaults to False.
# FEED_PLAIN = False

# Number of posts in Atom and RSS feeds.
# FEED_LENGTH = 10

# Include preview image as a <figure><img></figure> at the top of the entry.
# Requires FEED_PLAIN = False. If the preview image is found in the content,
# it will not be included again. Image will be included as-is, aim to optmize
# the image source for Feedly, Apple News, Flipboard, and other popular clients.
# FEED_PREVIEWIMAGE = True

# RSS_LINK is a HTML fragment to link the RSS or Atom feeds. If set to None,
# the base.tmpl will use the feed Nikola generates. However, you may want to
# change it for a FeedBurner feed or something else.
# RSS_LINK = None

# A search form to search this site, for the sidebar. You can use a Google
# custom search (https://www.google.com/cse/)
# Or a DuckDuckGo search: https://duckduckgo.com/search_box.html
# Default is no search form.
# (translatable)
# SEARCH_FORM = ""
#
# This search form works for any site and looks good in the "site" theme where
# it appears on the navigation bar:
#
# SEARCH_FORM = """
# <!-- DuckDuckGo custom search -->
# <form method="get" id="search" action="https://duckduckgo.com/"
#  class="navbar-form pull-left">
# <input type="hidden" name="sites" value="%s">
# <input type="hidden" name="k8" value="#444444">
# <input type="hidden" name="k9" value="#D51920">
# <input type="hidden" name="kt" value="h">
# <input type="text" name="q" maxlength="255"
#  placeholder="Search&hellip;" class="span2" style="margin-top: 4px;">
# <input type="submit" value="DuckDuckGo Search" style="visibility: hidden;">
# </form>
# <!-- End of custom search -->
# """ % SITE_URL
#
# If you prefer a Google search form, here's an example that should just work:
# SEARCH_FORM = """
# <!-- Google custom search -->
# <form method="get" action="https://www.google.com/search" class="navbar-form navbar-right" role="search">
# <div class="form-group">
# <input type="text" name="q" class="form-control" placeholder="Search">
# </div>
# <button type="submit" class="btn btn-primary">
#   <span class="glyphicon glyphicon-search"></span>
# </button>
# <input type="hidden" name="sitesearch" value="%s">
# </form>
# <!-- End of custom search -->
# """ % SITE_URL

# Use content distribution networks for jQuery, twitter-bootstrap css and js,
# and html5shiv (for older versions of Internet Explorer)
# If this is True, jQuery and html5shiv are served from the Google CDN and
# Bootstrap is served from BootstrapCDN (provided by MaxCDN)
# Set this to False if you want to host your site without requiring access to
# external resources.
# USE_CDN = False

# Check for USE_CDN compatibility.
# If you are using custom themes, have configured the CSS properly and are
# receiving warnings about incompatibility but believe they are incorrect, you
# can set this to False.
# USE_CDN_WARNING = True

# Extra things you want in the pages HEAD tag. This will be added right
# before </head>
# (translatable)
# EXTRA_HEAD_DATA = ""
# Google Analytics or whatever else you use. Added to the bottom of <body>
# in the default template (base.tmpl).
# (translatable)
# BODY_END = ""

# The possibility to extract metadata from the filename by using a
# regular expression.
# To make it work you need to name parts of your regular expression.
# The following names will be used to extract metadata:
# - title
# - slug
# - date
# - tags
# - link
# - description
#
# An example re is the following:
# '.*\/(?P<date>\d{4}-\d{2}-\d{2})-(?P<slug>.*)-(?P<title>.*)\.rst'
# (Note the '.*\/' in the beginning -- matches source paths relative to conf.py)
# FILE_METADATA_REGEXP = None

# If you hate "Filenames with Capital Letters and Spaces.md", you should
# set this to true.
UNSLUGIFY_TITLES = True

# Additional metadata that is added to a post when creating a new_post
# ADDITIONAL_METADATA = {}

# Nikola supports Open Graph Protocol data for enhancing link sharing and
# discoverability of your site on Facebook, Google+, and other services.
# Open Graph is enabled by default.
# USE_OPEN_GRAPH = True

# Nikola supports Twitter Card summaries, but they are disabled by default.
# They make it possible for you to attach media to Tweets that link
# to your content.
#
# IMPORTANT:
# Please note, that you need to opt-in for using Twitter Cards!
# To do this please visit https://cards-dev.twitter.com/validator
#
# Uncomment and modify to following lines to match your accounts.
# Images displayed come from the `previewimage` meta tag.
# You can specify the card type by using the `card` parameter in TWITTER_CARD.
# TWITTER_CARD = {
#     # 'use_twitter_cards': True,  # enable Twitter Cards
#     # 'card': 'summary',          # Card type, you can also use 'summary_large_image',
#                                   # see https://dev.twitter.com/cards/types
#     # 'site': '@website',         # twitter nick for the website
#     # 'creator': '@username',     # Username for the content creator / author.
# }

# If webassets is installed, bundle JS and CSS into single files to make
# site loading faster in a HTTP/1.1 environment but is not recommended for
# HTTP/2.0 when caching is used. Defaults to True.
USE_BUNDLES = False

# Plugins you don't want to use. Be careful :-)
# DISABLED_PLUGINS = ["render_galleries"]

# Special settings to disable only parts of the indexes plugin (to allow RSS
# but no blog indexes, or to allow blog indexes and Atom but no site-wide RSS).
# Use with care.
# DISABLE_INDEXES_PLUGIN_INDEX_AND_ATOM_FEED = False
# DISABLE_INDEXES_PLUGIN_RSS_FEED = False

# Add the absolute paths to directories containing plugins to use them.
# For example, the `plugins` directory of your clone of the Nikola plugins
# repository.
# EXTRA_PLUGINS_DIRS = []

# Add the absolute paths to directories containing themes to use them.
# For example, the `v7` directory of your clone of the Nikola themes
# repository.
# EXTRA_THEMES_DIRS = []

# List of regular expressions, links matching them will always be considered
# valid by "nikola check -l"
# LINK_CHECK_WHITELIST = []

# If set to True, enable optional hyphenation in your posts (requires pyphen)
# Enabling hyphenation has been shown to break math support in some cases,
# use with caution.
# HYPHENATE = False

# The <hN> tags in HTML generated by certain compilers (reST/Markdown)
# will be demoted by that much (1 → h1 will become h2 and so on)
# This was a hidden feature of the Markdown and reST compilers in the
# past.  Useful especially if your post titles are in <h1> tags too, for
# example.
# (defaults to 1.)
# DEMOTE_HEADERS = 1

# Docutils, by default, will perform a transform in your documents
# extracting unique titles at the top of your document and turning
# them into metadata. This surprises a lot of people, and setting
# this option to True will prevent it.
# NO_DOCUTILS_TITLE_TRANSFORM = False

# If you don’t like slugified file names ([a-z0-9] and a literal dash),
# and would prefer to use all the characters your file system allows.
# USE WITH CARE!  This is also not guaranteed to be perfect, and may
# sometimes crash Nikola, your web server, or eat your cat.
# USE_SLUGIFY = True

# Templates will use those filters, along with the defaults.
# Consult your engine's documentation on filters if you need help defining
# those.
# TEMPLATE_FILTERS = {}

# Put in global_context things you want available on all your templates.
# It can be anything, data, functions, modules, etc.
GLOBAL_CONTEXT = {}

# Add functions here and they will be called with template
# GLOBAL_CONTEXT as parameter when the template is about to be
# rendered
GLOBAL_CONTEXT_FILLER = []
