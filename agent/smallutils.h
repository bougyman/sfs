#ifndef _SMALLUTILS_H_
#define _SMALLUTILS_H_

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define New new
#define vNew (void) New

extern char *progname;

void warnx (char *fmt, ...);
void warn (char *fmt, ...);
void fatal (char *fmt, ...);

#define assert(x) \
  if (!(x)) \
    fatal ("%s:%d: assertion failed: %s\n", __FILE__, __LINE__, #x);

class str {
  char *chars;
  size_t size;
  size_t len;

public:
  void init () { size = len = 0; }
  void clear () { if (size > 0) delete[] chars; init (); }
  str () { init (); }
  str (str &s) { init (); copy (s); }
  str (char *s) { init (); copy (s); }
  ~str () { clear (); }

  size_t length () const { return len; }
  char *cstr () const { return chars; }
  char *release () { size = 0; return chars; }
  int cmp (str &s) const { return strcmp (chars, s.chars); }
  int cmp (char *s) const { return strcmp (chars, s); }

  void append (const char *s, size_t slen);
  void append (const str &s) { append (s.cstr (), s.length ()); }
  void append (const char *s) { append (s, strlen (s)); }
  void append (char c) { append (&c, 1); }

  void copy (const char *s, size_t slen) { clear (); append (s, slen); }
  void copy (const str &s) { clear (); append (s); }
  void copy (const char *s) { clear (); append (s); }

  bool split (char c, str &before, str &after);
};

inline str &operator<< (str &s, const char *ss)
{
  s.append (ss);
  return s;
}

inline str &operator<< (str &s, const str &ss)
{
  s.append (ss);
  return s;
}

char *lastpathcomponent (char *s);

#endif /* ndef _SMALLUTILS_H_ */
