// -*-c++-*-
/* $Id: sexpr.h,v 1.2 2004/06/05 20:34:18 dm Exp $ */

#ifndef _SEXPR_H_
#define _SEXPR_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "smallutils.h"

/*
 * simple lisp-like objects plus an s-expression reader to
 * create them from a printed representation
 */

/*
 * objects
 */

typedef enum {
  gtype_bottom,
  gtype_integer,
  gtype_symbol,
  gtype_string,
  gtype_pair
} gtype;

class gob {
public:
  gtype type;

public:
  gob (gtype t) : type (t) {}
  virtual ~gob () {}
  virtual int cmp (gob *g) const { fatal ("nonpareil"); return 0; }
  virtual bool equal (gob *g) const { return cmp (g) == 0; }
  virtual int fprint (FILE *f) const { return fwrite (f); }
  virtual int fwrite (FILE *f) const = 0;
  int print () const { return fprint (stdout); }
  int write () const { return fwrite (stdout); }
};

class gbottom : public gob {
public:
  gbottom () : gob (gtype_bottom) {}
  bool equal (gob *g) const { return g->type == gtype_bottom; }
  int fwrite (FILE *f) const;
};

extern gbottom *bottom;

inline bool g_null (const gob *o) { return o == bottom; }

class ginteger : public gob {
private:
  const unsigned long val;

public:
  ginteger (unsigned long i) : gob (gtype_integer), val (i) {}
  unsigned long value () const { return val; }
  int cmp (gob *g) const;
  int fwrite (FILE *f) const;
};

class gstring : public gob {
private:
  str chars;

public:
  gstring () : gob (gtype_string) {}
  gstring (str &s) : gob (gtype_string) { chars.copy (s); }
  gstring (char *s) : gob (gtype_string) { chars.copy (s); }
  char *cstr () const { return chars.cstr (); }
  void append (char c) { chars.append (c); }
  int cmp (gob *g) const;
  int fprint (FILE *f) const;
  int fwrite (FILE *f) const;
};

class gsymbol : public gob {
  friend gsymbol *g_symbol (char *s);
  friend gsymbol *g_symbol (str &s);

private:
  struct strtab_ent {
    unsigned long refcount;
    strtab_ent *next;
    strtab_ent **prevp;
    str s;
    void init () { refcount = 0; next = NULL; prevp = NULL; }
    strtab_ent (str &ss) { init (); s.copy (ss); }
    strtab_ent (char *ss) { init (); s.copy (ss); }
    void incref () { refcount++; }
    void decref ();
  };

public:			       // This has to be public for the_strtab
  struct strtab {
    strtab_ent *head;
    strtab () : head (NULL) {}
    strtab_ent *insert (char *);
  };
private:

  strtab_ent *ent;

  gsymbol (strtab_ent *ent) : gob (gtype_symbol), ent (ent) {}

public:
  ~gsymbol () {
    ent->decref ();
  }

  char *name () const {
    return ent->s.cstr ();
  }

  bool equal (gob *g) const;

  int fwrite (FILE *f) const {
    return fprintf (f, "%s", ent->s.cstr ());
  }
};

gsymbol *g_symbol (char *s);
gsymbol *g_symbol (str &s);

class gpair : public gob {
public:
  gob *car;
  gob *cdr;

  gpair () : gob (gtype_pair), car (bottom), cdr (bottom) {}
  gpair (gob *car, gob *cdr) : gob (gtype_pair), car (car), cdr (cdr) {}
  gob *first () const { return car; }
  gob *rest () const { return cdr; }
  bool equal (gob *g) const;
  int fwrite (FILE *f) const { return output (f, true); }
  int fprint (FILE *f) const { return output (f, false); }
private:
  int output (FILE *f, bool writing) const;
};

#define GTYPE_PRED(t) \
inline bool isg##t (gob *ob) { return ob->type == gtype_##t; }

GTYPE_PRED (bottom);
GTYPE_PRED (integer);
GTYPE_PRED (string);
GTYPE_PRED (symbol);
GTYPE_PRED (pair);

#define GTYPE_CONV(t) \
inline g##t *tog##t (gob *ob) { \
  return (ob && ob->type == gtype_##t) ? static_cast<g##t *> (ob) : NULL; }

GTYPE_CONV (integer);
GTYPE_CONV (string);
GTYPE_CONV (symbol);
GTYPE_CONV (pair);


/*
 * streams
 */

class stream {
public:
  virtual int get () = 0;
  virtual int unget (int c) = 0;
  virtual int error () = 0;
  virtual int eof () = 0;
};

class file_stream : public stream {
public:
  FILE *file;
  file_stream (FILE *f) : file (f) {}
  int get () { return fgetc (file); }
  int unget (int c) { return ungetc (c, file); }
  int error () { return ferror (file); }
  int eof () { return feof (file); }
};

class buf_stream : public stream {
private:
  bool err;
  const char *p, *start, *end;

public:
  buf_stream (const char *b, size_t len)
    : err (false), p (b), start (b), end (b + len) {}
  int get () { return (p < end) ? *(p++) : EOF; }
  int unget (int c);
  int error () { return err; }
  int eof () { return p == end; }
};


/*
 * read
 */

gob *g_read (stream *s);


/*
 * utils
 */

gob *g_nth (gob *listob, unsigned int n);
bool g_equal (gob *a, gob *b);
gob *g_cons (gob *a, gob *b);
gob *g_list (int n, ...);

inline gob *g_list (gob *g1) {
  return g_list (1, g1);
}
inline gob *g_list (gob *g1, gob *g2) {
  return g_list (2, g1, g2);
}
inline gob *g_list (gob *g1, gob *g2, gob *g3) {
  return g_list (3, g1, g2, g3);
}
inline gob *g_list (gob *g1, gob *g2, gob *g3, gob *g4) {
  return g_list (4, g1, g2, g3, g4);
}

#endif /* ndef _SEXPR_H_ */
