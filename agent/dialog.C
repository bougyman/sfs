/*
 * open a dialog whose contents are described by an s-expression of
 * the form:
 *
 * (window "window-name"
 *      ELM ...)
 *
 * where ELM can be any of:
 *
 * "string"             // the text within quotation marks is drawn
 * (hspace N)           // N pixels of horizontal space
 * (vspace N)           // N pixels of vertical space
 * (ignore ELM ...)     // nothing
 * (button "name")      // a button with the given name
 * (radio N)            // a radio-button with the value N
 * (radioset ELM ...)   // any radio elements among ELM will be
 *                      //   mutually exclusive
 * (row ELM ...)        // the elements are arranged left-to-right
 * (col ELM ...)        // the elements are arranged top-to-bottom                      
 */

// XXX: todo: memory management!

#include "smallutils.h"
#include "sexpr.h"
#include "gui.C"

#define TEXT_FONT_DEFAULT FIXED_MEDIUM_18
#define BUTTON_FONT_DEFAULT FIXED_20
const char *text_fontname = TEXT_FONT_DEFAULT;
const char *button_fontname = BUTTON_FONT_DEFAULT;

widg *make_widget (window *, dist, dist, gob *);

void
warncontext (gob *ob)
{
  warn ("in: ");
  ob->fprint (stderr);
  warn ("\n");
}

widg *
make_vspace (window *w, dist x, dist y, gob *expr)
{
  ginteger *num = toginteger (g_nth (expr, 1));
  if (!num) {
    warncontext (expr);
    fatal ("incorrect arguments to VSPACE expression");
  }
  return New space_widg (x, y + num->value ());
}

widg *
make_hspace (window *w, dist x, dist y, gob *expr)
{
  ginteger *num = toginteger (g_nth (expr, 1));
  if (!num) {
    warncontext (expr);
    fatal ("incorrect arguments to HSPACE expression");
  }
  return New space_widg (x + num->value (), y);
}

widg *
make_ignore (window *w, dist x, dist y, gob *expr)
{
  return New space_widg (x, y);
}

widg *
make_row (window *win, dist x, dist y, gob *expr)
{
  dist ymax = y;
  gob *argsob = (togpair (expr))->rest ();
  while (!g_null (argsob))
  {
    gpair *args = togpair (argsob);
    assert (args);
    gob *ob = args->first ();
    argsob = args->rest ();

    widg *w = make_widget (win, x, y, ob);
    x = w->right ();
    ymax = (w->bottom () > ymax) ? w->bottom () : ymax;
  }
  return New space_widg (x, ymax);
}

widg *
make_col (window *win, dist x, dist y, gob *ob)
{
  dist xmax = x;
  gob *argsob = (togpair (ob))->rest ();
  while (!g_null (argsob))
  {
    gpair *args = togpair (argsob);
    assert (args);
    gob *ob = args->first ();
    argsob = args->rest ();

    widg *w = make_widget (win, x, y, ob);
    y = w->bottom ();
    xmax = (w->right () > xmax) ? w->right () : xmax;
  }
  return New space_widg (xmax, y);
}

void quit ();

widg *
make_button (window *w, dist x, dist y, gob *expr)
{
  font_t *buttonfont = w->get_font (button_fontname);
  if (!buttonfont)
    fatal ("couldn't find font named '%s'", button_fontname);

  gstring *name = togstring (g_nth (expr, 1));
  if (!name) {
    warncontext (expr);
    fatal ("incorrect arguments to BUTTON expression");
  }
  return New button_widg (w, x, y, buttonfont, name->cstr (), &quit);
}

radio_set *the_radio_set = NULL;

widg *
make_radioset (window *w, dist x, dist y, gob *expr)
{
  the_radio_set = New radio_set;
  return make_col (w, x, y, expr);
}

gsymbol *selected = g_symbol ("selected");

widg *
make_radio (window *w, dist x, dist y, gob *expr)
{
  ginteger *val = toginteger (g_nth (expr, 1));
  if (!val) {
    warncontext (expr);
    fatal ("incorrect arguments to RADIO expression");
  }

  radio_widg *r = New radio_widg (w, x, y, val->value ());
  if (the_radio_set)
    the_radio_set->add (r);

  gsymbol *state = togsymbol (g_nth (expr, 2));
  if (state && g_equal (state, selected))
    r->select ();

  return r;
}

typedef widg * (*maker_func) (window *w, dist x, dist y, gob *args);
struct maker_entry {
  gsymbol *name;
  maker_func f;
};
#define MAKER_ENTRY(x) { g_symbol (#x), make_##x }
maker_entry maker_table[] = {
  MAKER_ENTRY (hspace),
  MAKER_ENTRY (vspace),
  MAKER_ENTRY (ignore),
  MAKER_ENTRY (button),
  MAKER_ENTRY (radio),
  MAKER_ENTRY (radioset),
  MAKER_ENTRY (row),
  MAKER_ENTRY (col),
  { NULL, NULL }
};

widg *
make_widget (window *w, dist x, dist y, gob *ob)
{
  if (gstring *s = togstring (ob)) {
    font_t *textfont = w->get_font (text_fontname);
    if (!textfont)
      fatal ("couldn't find font named '%s'", text_fontname);
    return New text_widg (w, x, y, textfont, s->cstr ());
  }
  else if (gpair *p = togpair (ob)) {
    gob *func = p->first ();
    for (maker_entry *me = maker_table; me->f; me++)
      if (g_equal (me->name, func))
        return (*me->f) (w, x, y, ob);
  }
  warncontext (ob);
  fatal ("unrecognized expression");
  return NULL;
}

window *the_window;
int exitvalue = -1;

void
quit ()
{
  the_window->stop ();
  exitvalue = the_radio_set ? the_radio_set->value () : -1;
}

#define MARGIN 30

int
dialog_main (const char *input)
{
  gob *g = g_read (New buf_stream (input, strlen (input)));
  if (!g) {
    warn ("error reading s-expression");
    return -1;
  }
  gsymbol *protocol = togsymbol (g_nth (g, 0));
  if (!g_equal (protocol, g_symbol ("window"))) {
    warn ("gui expression should be of the form (window ...)");
    return -1;
  }

  gstring *name = togstring (g_nth (g, 1));
  if (!name) {
    warn ("first argument to window expression must be a string");
    return -1;
  }

  window *w = the_window = New window;
  w->opendisplay ();
  widg *contents = make_col (w, MARGIN, MARGIN, (togpair (g))->rest ());
  w->init (name->cstr (), contents->right () + MARGIN,
                          contents->bottom () + MARGIN);
  w->start ();
  w->flush ();
  return exitvalue;
}

#define SHIFT { argc--; argv++; }

bool
process_dialog_args (int argc, char **argv)
{
  while (argc) {
    if (strcmp (argv[0], "-fn") == 0) {
      SHIFT;
      if (!argc)
        return false;
      text_fontname = argv[0];
    }
    else if (strcmp (argv[0], "-fb") == 0) {
      SHIFT;
      if (!argc)
        return false;
      button_fontname = argv[0];
    }
    else
      return false;
    SHIFT;
  }
  return true;
}
