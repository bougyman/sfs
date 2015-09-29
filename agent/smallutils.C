#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "smallutils.h"

char *progname = NULL;

#define WARNPROGNAME \
  if (progname) \
    fprintf (stderr, "%s: ", progname);
#define WARNXMAIN \
  va_list ap; \
  va_start (ap, fmt); \
  vfprintf (stderr, fmt, ap); \
  va_end (ap);
#define WARNMAIN WARNPROGNAME; WARNXMAIN

void warnx (char *fmt, ...) {
  WARNXMAIN;
}

void warn (char *fmt, ...) {
  WARNMAIN;
}

void fatal (char *fmt, ...)
{
  WARNMAIN;
  fprintf (stderr, "\n");
  exit (1);
}

void
str::append (const char *s, size_t slen)
{
  size_t newlen = len + slen;
  if (newlen >= size) {
    int newsize = newlen + 32;
    char *newchars = New char[newsize];
    if (size > 0) {
      memcpy (newchars, chars, len);
      delete[] chars;
    }
    chars = newchars;
    size = newsize;
  }
  memcpy (chars + len, s, slen);
  len = newlen;
  chars[len] = '\0';
}

bool
str::split (char c, str &before, str &after)
{
  const char *cp = strchr (chars, c);
  if (!cp)
    return false;
  size_t i = cp - chars;
  before.copy (chars, i);
  if (i < len)
    after.copy (cp + 1, len - i - 1);
  else
    after.clear ();
  return true;
}

char *
lastpathcomponent (char *s)
{
  for (char *p = s; *p; p++)
    if (*p == '/')
      s = p + 1;
  return s;
}

