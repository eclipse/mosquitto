#ifndef PATH_HELPER_H
#define PATH_HELPER_H

#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/* returns <current source directory>/<relpath> written to <dest>  */
void cat_sourcedir_with_relpath(char* dest, const char* relpath) {
  strcpy(dest,TEST_SOURCE_DIR);
  strcat(dest, relpath);
}

#endif
