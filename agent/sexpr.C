#include "smallutils.h"
#include "sexpr.h"

/*
 * object implementations
 */

static gbottom the_bottom;
gbottom *bottom = &the_bottom;

// this macro is brittle and only for internal use.
// in general, use toginteger (), etc.
#define TOGTYPE(t,g) ((g->type == gtype_##t) ? static_cast<g##t*> (g) : NULL)

int
gbottom::fwrite (FILE *f) const {
  return fprintf (f, "()");
}

int
ginteger::cmp (gob *g) const
{
  ginteger *gi = TOGTYPE (integer, g);
  assert (gi);
  return val - gi->value ();
}

int
ginteger::fwrite (FILE *f) const {
  return fprintf (f, "%ld", val);
}

int
gstring::cmp (gob *g) const
{
  gstring *gs = TOGTYPE (string, g);
  assert (gs);
  return strcmp (cstr (), gs->cstr ());
}

int
gstring::fprint (FILE *f) const {
  return fprintf (f, "%s", cstr ());
}

int
gstring::fwrite (FILE *f) const
{
  int n = 0;
  fputc ('"', f); n++;
  for (char *cp = chars.cstr (); *cp; cp++)
    switch (*cp) {
      case '\n':
        fputc ('\\', f); n++;
        fputc ('n', f); n++;
        break;
      case '\\':
      case '"':
        fputc ('\\', f); n++;
      default:
        fputc (*cp, f); n++;
    }
  fputc ('"', f); n++;
  return n;
}

void
gsymbol::strtab_ent::decref ()
{
  assert (refcount);
  if (!--refcount) {
    *prevp = next;
    if (next)
      next->prevp = prevp;
    delete this;
  }
}

gsymbol::strtab_ent *
gsymbol::strtab::insert (char *ss)
{
  strtab_ent *ent;
  for (ent = head; ent; ent = ent->next)
    if (ent->s.cmp (ss) == 0) {
      ent->incref ();
      return ent;
    }

  ent = New strtab_ent (ss);
  ent->refcount++;
  ent->next = head;
  if (head)
    head->prevp = &(ent->next);
  head = ent;
  return ent;
}

static gsymbol::strtab the_strtab; 

gsymbol *
g_symbol (char *s) {
  return New gsymbol (the_strtab.insert (s));
}

gsymbol *
g_symbol (str &s) {
  return New gsymbol (the_strtab.insert (s.cstr ()));
}

bool
gsymbol::equal (gob *g) const
{
  gsymbol *gs = TOGTYPE (symbol, g);
  return gs && gs->ent == ent;
}

bool
gpair::equal (gob *g) const
{
  gpair *gp = TOGTYPE (pair, g);
  return gp && gp->car->equal (car) && gp->cdr->equal (cdr);
}

int
gpair::output (FILE *f, bool writing) const
{
  int n = 0;

#define NOUTC(x) do { \
  int nn = x; \
  if (nn == EOF) \
    return -1; \
  else n++; \
} while (0)

#define NOUT(x) do { \
  int nn = x; \
  if (nn == -1) \
    return -1; \
  else n += nn; \
} while (0)

  NOUTC (fputc ('(', f));
  const gob *ob = this;
  while (!g_null (ob)) {
    assert (ob->type == gtype_pair);
    const gpair *p = static_cast<const gpair *> (ob);
    if (writing)
      NOUT (p->car->fwrite (f));
    else
      NOUT (p->car->fprint (f));
    ob = p->cdr;
    if (!g_null (ob))
      NOUTC (fputc (' ', f));
  }
  NOUTC (fputc (')', f));
  return n;
}

int
buf_stream::unget (int c)
{
  if (p == end && c == EOF) {
    p--;
    return EOF;
  }
  else if (p > start && *(--p) == c) {
    return c;
  }
  else {
    err = true;
    return EOF;
  }
}


/*
 * read
 */

typedef union {
  struct { gpair *elms; gpair *elmstail; } list;
  str *chars;
} gread_state;

typedef void (*gread_func) (gread_state *);

struct gread_frame {
  gread_func function;
  gread_state *arg;
  gread_frame *next;
  gread_frame (gread_func f, gread_state *arg, gread_frame *next)
    : function (f), arg (arg), next (next) {}
};

static stream *gread_stream;
static gob *gread_res;
static gread_frame *gread_stack;
static bool gread_error;

inline int gget () { return gread_stream->get (); }
inline void gunget (int c) { gread_stream->unget (c); }

void gread_gob (gread_state *);

gob *
g_read (stream *s)
{
  gread_stream = s;

  gread_stack = New gread_frame (gread_gob, NULL, NULL);
  gread_res = NULL;
  gread_error = false;
  while (gread_stack && !gread_error) {
    gread_frame *rest = gread_stack->next;
    gread_func f = gread_stack->function;
    gread_state *arg = gread_stack->arg;
    delete gread_stack;
    gread_stack = rest;
    (*f) (arg);
  }
  return gread_error ? NULL : gread_res;
}

#define gpush(f, arg) \
  gread_stack = New gread_frame (f, arg, gread_stack);

#define ggoto(f, arg) do { \
  gpush (f, arg); \
  return; \
} while (0)

#define greturn(x) do { \
  gread_res = x; \
  return; \
} while (0)

#define gerror() do { \
  gread_error = true; \
  return; \
} while (0)

void
gread_string (gread_state *state)
{
  int c = gget ();
  switch (c) {
    case EOF:
      gerror ();
    case '"':
      {
        gstring *string = New gstring (*(state->chars));
        delete state->chars;
        delete state;
        greturn (string);
      }
    case '\\':
      c = gget ();
      switch (c) {
        case EOF:
          gerror ();
        case 'n':
          state->chars->append ('\n');
          ggoto (gread_string, state);
      }
      // else fall through
    default:
      state->chars->append (c);
      ggoto (gread_string, state);
  }
}

inline bool
issymbolpunct (int c)
{
  static char chars[] = "-?!*:";
  for (char *cp = chars; *cp != '\0'; cp++)
    if (*cp == c)
      return true;
  return false;
}

inline bool
issymbolchar (int c)
{
  return isalnum (c) || issymbolpunct (c);
}

void
gread_symbol (gread_state *state)
{
  int c = gget ();
  if (issymbolchar (c)) {
    state->chars->append (tolower (c));
    ggoto (gread_symbol, state);
  }
  else {
    gunget (c);
    gsymbol *sym = g_symbol (*(state->chars));
    delete state->chars;
    delete state;
    greturn (sym);
  }
}

void
gread_integer (gread_state *state)
{
  int c = gget ();
  if (isdigit (c)) {
    state->chars->append (c);
    ggoto (gread_integer, state);
  }
  else {
    gunget (c);
    // XX: strtoul?
    ginteger *num = New ginteger (atol (state->chars->cstr ()));
    delete state->chars;
    delete state;
    greturn (num);
  }
}

void
consume_whitespace ()
{
  while (1) {
    int c = gget ();
    if (isspace (c))
      continue;
    else if (c == ';') {
      for (; c != EOF && c != '\n' && c != '\r'; c = gget ()) ;
    }
    else {
      gunget (c);
      break;
    }
  }
}

void
gread_list (gread_state *state)
{
  if (gread_res) {
    gpair *newpair = New gpair (gread_res, bottom);
    gpair *head = state->list.elms;
    gpair *tail = state->list.elmstail;
    if (tail) {
      tail->cdr = newpair;
      tail = newpair;
    }
    else
      head = tail = newpair;
    state->list.elms = head;
    state->list.elmstail = tail;
  }

  consume_whitespace ();
  int c = gget ();
  switch (c) {
    case EOF:
      gerror ();
    case ')':
      {
        gpair *elms = state->list.elms;
        delete state;
        if (elms)
          greturn (elms);
        else
          greturn (bottom);
      }
    default:
      gunget (c);
      gpush (gread_list, state);
      ggoto (gread_gob, NULL);
  }
}

void
gread_gob (gread_state *ignore)
{
  consume_whitespace ();
  int c = gget ();

  switch (c) {
    case EOF:
      gerror (); // unexpected end of input
    case '(':
      {
      gread_res = NULL;
      gread_state *state = New gread_state;
      state->list.elms = state->list.elmstail = NULL;
      ggoto (gread_list, state);
      }
    case ')':
      gerror (); // unbalanced parentheses
    case '"':
      {
      gread_state *state = New gread_state;
      state->chars = New str;
      ggoto (gread_string, state);
      }
    default:
      if (isdigit (c)) {
        gread_state *state = New gread_state;
        state->chars = New str;
        state->chars->append (c);
        ggoto (gread_integer, state);
      }
      else if (issymbolchar (c)) {
        gread_state *state = New gread_state;
        state->chars = New str;
        state->chars->append (tolower (c));
        ggoto (gread_symbol, state);
      }
      else
        gerror (); // unexpected character
  }
}


/*
 * utils
 */

gob *g_nth (gob *listob, unsigned int n)
// return the Nth value of the list, or NULL
{
  gob *ob = NULL;
  for (; n + 1; n--) {
    if (g_null (listob))
      return NULL;
    gpair *list = togpair (listob);
    if (!list)
      return NULL;
    ob = list->car;
    listob = list->cdr;
  }
  return ob;
}

bool g_equal (gob *a, gob *b)
{
  return a->type == b->type
         && a->equal (b);
}

gob *g_cons (gob *a, gob *b) { return New gpair (a, b); }

gob *g_list (int n, ...)
{
  gpair *head = NULL, *tail = NULL;
  va_list ap;
  va_start (ap, n);
  while (n--) {
    gpair *newpair = New gpair (va_arg (ap, gob *), bottom); 
    if (!head)
      head = tail = newpair;
    else {
      tail->cdr = newpair;
      tail = newpair;
    }
  }
  va_end (ap);
  if (head)
    return head;
  else
    return bottom;
}

#ifdef SEXPR_DEBUG
int
main (int argc, char **argv)
{
  stream *s = (argc > 1) ? New buf_stream (argv[1], strlen (argv[1]))
                         : New file_stream (stdin);
  gob *g = g_read (s);
  if (g)
    g->fwrite (stderr);
  else
    fprintf (stderr, "-- Error reading input");
  fprintf (stderr, "\n");
}
#endif /* SEXPR_DEBUG */

