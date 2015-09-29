/*
 * a simple widget layer on top of Xlib
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include "smallutils.h"

#define FIXED_MEDIUM_18 "-misc-fixed-medium-*-*-*-18-*-*-*-*-*-*-*"
#define FIXED_20 "-misc-fixed-*-*-*-*-20-*-*-*-*-*-*-*"
#define HELVETICA_MEDIUM_17 "-*-helvetica-medium-r-*-*-17-*-*-*-*-*-*-*"
#define HELVETICA_18 "-*-helvetica-*-r-*-*-18-*-*-*-*-*-*-*"

typedef int dist;

struct point {
  dist x; dist y;
  point (dist x, dist y) : x (x), y (y) {}
};

struct rect {
  point ul;
  point lr;
  rect (dist x, dist y, dist w, dist h)
    : ul (x, y), lr (x + w, y + h) {}
  rect (point p, dist w, dist h)
    : ul (p.x - w/2, p.y - h/2), lr (p.x + w/2, p.y + h/2) {}
  dist width () { return lr.x - ul.x; }
  dist height () { return lr.y - ul.y; }
  bool contains (point p) {
    return p.x >= ul.x && p.x <= lr.x && p.y >= ul.y && p.y <= lr.y;
  }
};

struct window;

struct widg {
  window *w;
  widg *next;

  widg (window *w);
  void dirty ();
  virtual void draw () {}
  virtual void mouseup (point p) {}
  virtual dist bottom () const = 0;
  virtual dist right () const = 0;
};

typedef XFontStruct font_t;
 
void
set_dialog_properties (Display *d, Window w, char *name, int width, int height)
{
  XTextProperty nameprop;
  if (!XStringListToTextProperty (&name, 1, &nameprop)) {
    warn ("XStringListToTextProperty failed\n");
    return;
  }
  XSetWMName (d, w, &nameprop);

  XSizeHints *sh = XAllocSizeHints ();
  sh->base_width = sh->min_width = sh->max_width = width;
  sh->base_height = sh->min_height = sh->max_height = height;
  sh->flags = PBaseSize | PMinSize | PMaxSize;
  XSetWMNormalHints (d, w, sh);
  XFree (sh);
}

struct window
{
  dist width, height;
  Display *display;
  GC gc;
  Window win;
  unsigned long background_pixel;
  unsigned long foreground_pixel;
  unsigned long gray_pixel;
  widg *widgs, *widgs_tail;
  int redraw_requests;
  bool done;

  window () : display (NULL), widgs (NULL), done (false) {}

  ~window ()
  {
    if (display)
      XCloseDisplay(display);
  }

  font_t *get_font (const char *name) { return XLoadQueryFont(display, name); }

  void please_redraw () { redraw_requests++; }

  void addwidg (widg *w) {
    w->next = NULL;
    if (!widgs)
      widgs = widgs_tail = w;
    else {
      widgs_tail->next = w;
      widgs_tail = w;
    }
  }

  void draw ()
  {
    XSetForeground (display, gc, gray_pixel);
    XFillRectangle (display, win, gc, 0, 0, width, height);

    for (widg *w = widgs; w; w = w->next) {
      default_colors ();
      w->draw ();
    }
  }

  void opendisplay ()
  {
    if (!(display = XOpenDisplay(":0"))) {
        fprintf(stderr, "Cannot connect to X server\n");
        exit (1);
    }
  }

  void init (char *name, dist width, dist height)
  {
    int screen_num = DefaultScreen(display);
    int screen_width = DisplayWidth(display, screen_num);
    int screen_height = DisplayHeight(display, screen_num);
    background_pixel = WhitePixel(display, screen_num);
    foreground_pixel = BlackPixel(display, screen_num);
    Window root_window = RootWindow(display, screen_num);

    int max_width = int (.9 * screen_width);
    int max_height = int (.9 * screen_height);
    width = width > max_width ? max_width : width;
    height = height > max_height ? max_height : height;
    int win_x = 30;
    int win_y = 30;
    int win_border_width = 2;

    win = XCreateSimpleWindow(display, root_window,
                              win_x, win_y, width, height,
                              win_border_width,
                              foreground_pixel, background_pixel);

    set_dialog_properties (display, win, name, width, height);

    Visual* default_visual = DefaultVisual(display, DefaultScreen(display));
    Colormap colormap = XCreateColormap(display, win, default_visual,
                                        AllocNone);
    XColor gray;
    // if (!XAllocColor (display, colormap, &gray))
    if (!XAllocNamedColor (display, colormap, "lightgray", &gray, &gray))
      fatal ("can't allocate gray");
    gray_pixel = gray.pixel;

    unsigned long valuemask = 0;
    XGCValues values;
    gc = XCreateGC(display, win, valuemask, &values);
    if (gc < 0) {
      fprintf(stderr, "XCreateGC failed\n");
    }

    unsigned int line_width = 1;
    int line_style = LineSolid;
    int cap_style = CapButt;
    int join_style = JoinMiter;
    XSetLineAttributes(display, gc,
                       line_width, line_style, cap_style, join_style);

    default_colors ();
    XSetFillStyle(display, gc, FillSolid);
  }

  void default_colors ()
  {
    XSetForeground(display, gc, foreground_pixel);
    XSetBackground(display, gc, background_pixel);
  }

  void invert_colors ()
  {
    XSetForeground(display, gc, background_pixel);
    XSetBackground(display, gc, foreground_pixel);
  }

  void flush () { XFlush (display); }

  void stop () { done = true; }

  void start ()
  {
    XMapWindow(display, win);
    XSync(display, False);
    draw ();
    flush ();

    XSelectInput(display, win,
                 ExposureMask | KeyPressMask | ButtonReleaseMask);

    redraw_requests = 0;

    XEvent ev;
    while (!done) {
      XNextEvent(display, &ev);
      switch (ev.type) {
        case Expose:
          if (ev.xexpose.count == 0)
            draw ();
          break;
  
        case ButtonRelease:
          {
          point pt (ev.xbutton.x, ev.xbutton.y);
          for (widg *w = widgs; w; w = w->next)
            w->mouseup (pt);
          break;
          }

        case KeyPress:
          break;
  
        default: /* ignore any other event types. */
          warn ("bad event\n");
          break;
      }

      if (redraw_requests) {
        draw ();
        redraw_requests = 0;
      }
    }
  }
};

widg::widg (window *w) : w (w) { if (w) w->addwidg (this); }
void widg::dirty () { w->please_redraw (); }

struct space_widg : public widg {
  dist r, b;
  space_widg (dist r, dist b) : widg (NULL), r (r), b (b) {}
  dist bottom () const { return b; }
  dist right () const { return r; }
};

struct text_widg : public widg {
  point pos;
  char *val;
  font_t *font;
  bool inverted;
  static const dist lpad = 0;
  dist wd, ht;

  text_widg (window *w, dist x, dist y, font_t *font, char *val)
    : widg (w), pos (x, y), val (val), font (font), inverted (false)
  { measure (); }

  void measure () {
    dist lw, offset = font->ascent;
    char *p, *s = val;
    wd = 0;
    while ((p = strchr (s, '\n'))) {
      lw = XTextWidth (font, s, p - s);
      if (lw > wd)
        wd = lw;
      offset += font->ascent + font->descent + lpad;
      s = p + 1;
    }
    lw = XTextWidth (font, s, strlen (s));
    if (lw > wd)
      wd = lw;
    ht = offset + font->descent;
  }

  dist height () const { return ht; }
  dist width () const { return wd; }
  dist bottom () const { return pos.y + ht; }
  dist right () const { return pos.x + wd; }
  dist bullet_y () const { return pos.y + font->ascent / 2; }

  void center_h () { pos.x += wd / 2; }
  void center_v () { pos.y += ht / 2; }
  void center () { center_h (); center_v (); }
  void right_justify () { pos.x -= wd; }

  void draw () {
    if (inverted)
      w->invert_colors ();
    XSetFont (w->display, w->gc, font->fid);

    dist offset = font->ascent;
    char *p, *s = val;
    while ((p = strchr (s, '\n'))) {
      draw_line (s, p - s, offset);
      offset += font->ascent + font->descent + lpad;
      s = p + 1;
    }
    draw_line (s, strlen (s), offset);
  }

  void draw_line (char *s, int len, dist offset)
  {
    XDrawString (w->display, w->win, w->gc, pos.x, pos.y + offset, s, len);
  }

  void invert () { inverted = true; dirty (); }
};

struct button_widg : public widg {
  void (*cb) ();
  text_widg text;
  rect box;
  bool inverted;
  static const dist hpad = 5;
  static const dist vpad = 5;

  button_widg (window *w, dist x, dist y, font_t *font, char *name,
               void (*cb) ())
    : widg (w), cb (cb), 
      text (w, x + hpad, y + vpad, font, name),
      box (x, y, text.width () + (2 * hpad), text.height () + (2 * vpad)),
      inverted (false)
  {}

  dist right () const { return box.lr.x; }
  dist bottom () const { return box.lr.y; }

  void draw ()
  {
    if (!inverted)
      w->invert_colors ();
    XFillRectangle (w->display, w->win, w->gc, box.ul.x, box.ul.y,
                                               box.width (), box.height ());
    w->default_colors ();
    XDrawRectangle (w->display, w->win, w->gc, box.ul.x, box.ul.y,
                                               box.width (), box.height ());
  }

  void invert ()
  {
    inverted = true;
    text.invert ();
    dirty ();
  }

  void mouseup (point p)
  {
    if (box.contains (p)) {
      invert ();
      (*cb) ();
    }
  }
};

struct radio_set;

struct radio_widg : public widg {
  point pos;
  rect bounds;
  static const dist outer = 7;
  static const dist inner = 4;
  bool selected;
  radio_widg *nextradio;
  radio_set *owner;
  const int value;

  radio_widg (window *w, dist x, dist y, int value = 0, bool selected = false)
    : widg (w), pos (x + outer, y + outer), bounds (pos, 2*outer, 2*outer),
      selected (selected), owner (NULL), value (value)
  {}

  dist right () const { return bounds.lr.x; }
  dist bottom () const { return bounds.lr.y; }

  void select ();
  void deselect () { selected = false; dirty (); }

  void draw () {
    w->invert_colors ();
    XFillArc (w->display, w->win, w->gc,
              pos.x - outer, pos.y - outer,
              2*outer, 2*outer, 0, 365*64);
    w->default_colors ();
    XDrawArc (w->display, w->win, w->gc,
              pos.x - outer, pos.y - outer,
              2*outer, 2*outer, 0, 365*64);
    if (selected)
      XFillArc (w->display, w->win, w->gc,
                pos.x - inner, pos.y - inner,
                2*inner, 2*inner, 0, 365*64);
  }

  void mouseup (point p) {
    if (bounds.contains (p)) {
      select ();
      dirty ();
    }
  }
};

struct radio_set {
  radio_widg *radios;
  radio_widg *selected;

  radio_set () : radios (NULL), selected (NULL) {}

  void add (radio_widg *r) {
    r->owner = this;
    r->nextradio = radios;
    radios = r;

    if (r->selected)
      selected = r;
  }

  void select_notify (radio_widg *which) {
    selected = which;
    for (radio_widg *r = radios; r; r = r->nextradio)
      if (r != which)
        r->deselect ();
  }

  void select_next () {
    if (selected && selected->nextradio)
      selected->nextradio->select ();
    else
      if (radios)
        radios->select ();
  }

  int value () { return selected ? selected->value : -1; }
};

void radio_widg::select () {
  if (owner)
    owner->select_notify (this);
  selected = true;
  dirty ();
}

