#include "rxx.h"
#include "err.h"

static void
splitpath (vec<str> &out, str in)
{
  const char *p = in.cstr ();
  const char *e = p + in.len ();
  const char *n;

  for (;;) {
    while (*p == '/')
      p++;
    for (n = p; n < e && *n != '/'; n++)
      ;
    if (n == p)
      return;
    out.push_back (str (p, n - p));
    p = n;
  }
}


/* Given a path, split it into two pieces:
   the parent directory path and the filename.

   Examples:

   path      parent   filename
   "/"       "/"      ""
   "/a"      "/"      "a"
   "/a/"     "/"      "a"
   "/a/b"    "/a"     "b"
   "/a/b/c"  "/a/b"   "c"
 */
static void
parentpath (str &parent, str &filename, str inpath)
{
  vec<str> ppv;
  parent = str ("/");
  filename = str ("");

  splitpath (ppv, inpath);

  if (ppv.size () == 0)
    return;

  filename = ppv.pop_back ();
  if (ppv.size () == 0)
    return;

  // What a non-intuitive way to do concatenation!
  parent = strbuf () << "/" << join (str("/"), ppv);
}



int
main (int argc, const char *argv[])
{
  if (argc < 2)
    return -1;

  str parent, filename;

  parentpath (parent, filename, str (argv[1]));

    warn << parent << "\n";
    warn << filename << "\n";

  return 0;

  vec<str> out;
  splitpath (out, argv[1]);
  str foo;

  while (out.size () > 0 && (foo = out.pop_front ()))
    warn << foo << "\n";
  return 0;

  str path (argv[1]);
  
  //  vec<str> out;
  static rxx r ("^(.*)/([^/]+)$");
  //  static rxx r ("^/*([^/]+)(/.*)?$");

  //  static rxx r ("^s%/[^/]*$%%");
  //   static rxx pathsplit ("^/*([^/]+)(/.*)?$");

  warn << "path: " << path << "\n";

  // path = path/r;


  if (r.search (path))
    {

      if (r.len(1) != -1)
	warn << r[1] << " -> ";
      if (r.len(2) != -1)
	warn << r[2] << "\n";
      warn << "r[0]: " << r[0] << "\n";
    }

  warn << split (&out, "/", path) << "\n";  
  for (unsigned int i=0; i< out.size(); i++)
    warn << out[i] << "\n";

  return 0;

}
