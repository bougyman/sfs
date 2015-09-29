#!/usr/bin/python

import sys
import os
import gtk
import pickle

FILE = os.getenv('HOME') + "/.sfs/confirm_state"
state = []

def trans_service(s):
  if s == "SFS_SFS":
    return "SFS File System"
  elif s == "SFS_REX":
    return "Remote Execution (REX)"
  else:
    return s

def trans_from(s):
  try:
    p = os.popen ("sfskey sesslist")
    for line in p:
      line = line.split()
      if line[0] == s:
        return line[1][1:-1]
  except:
    return s
  return s

def save_state(s):
  global state, FILE
  try:
    fh = open (FILE, 'w')
    state.insert (0, s)
    pickle.dump (state, fh)
    fh.close ()
  except:
    print "Could not save state!"
  print s

def load_state():
  global state, FILE
  try:
    fh = open (FILE, 'r')
    state = pickle.load (fh)
    fh.close ()
  except:
    print "Could not load state!"

def check_state():
  for i in ((cur_key, requestor, fqdn+","),
            (cur_key, requestor, domain+","),
            (cur_key, requestor, None)):
    if i in state:
      print "Match: ", i
      sys.exit (0)
    else:
      print "No match: ", i

def done(button, rs):
  i = 0
  for r in rs:
    if r.get_active():
      break
    i += 1

  if i == 0:
    sys.exit (1)
  elif i == 1:
    sys.exit (0)
  elif i == 2:
    save_state ((cur_key, requestor, fqdn+","))
    sys.exit (0)
  elif i == 3:
    save_state ((cur_key, requestor, domain+","))
    sys.exit (0)
  elif i == 4:
    save_state ((cur_key, requestor, None))
    sys.exit (0)
  else:
    sys.exit (1)

def ask(msg, options):
  win = gtk.Window()
  win.connect('destroy', lambda arg: sys.exit (1))
  win.set_title('SFS Authentication Request')
  win.set_default_size(600, 400)

  vbox = gtk.VBox()
  vbox.set_border_width(10)
  win.add(vbox)

  # Label
  label = gtk.Label()
  label.set_markup(msg)
  vbox.pack_start(label, gtk.FALSE, gtk.TRUE)

  # Radio buttons
  frame = gtk.Frame("Options")
  vbox2 = gtk.VBox()
  vbox2.set_border_width(10)
  frame.add (vbox2)

  r = None
  rs = [] 
  for o in options:
    r = gtk.RadioButton (r, o)
    r.set_use_underline (0)
    r.set_property ('can_focus', False)
    rs.append (r)
    vbox2.pack_start (r, padding=5)

  vbox.pack_start (frame, padding=10)

  # Ok button
  bbox = gtk.HButtonBox()
  button = gtk.Button(stock='gtk-ok')
  button.connect('clicked', done, rs)
  bbox.pack_start(button)

  vbox.pack_start(bbox, gtk.FALSE, gtk.FALSE)

  button.grab_focus()
  win.show_all()
  gtk.main()

def setup():
  msg = """<big>*****  SFS Authentication Request  *****</big><tt>

   <b>REQUEST FROM:</b> """ + requestor_trans + """
      <b>TO ACCESS:</b> """ + fqdn + """
   <b>WITH SERVICE:</b> """ + trans_service (service) + """
   <b>   USING KEY:</b> <u>""" + cur_key + "</u></tt>"

  o = []
  o.append ("Reject the authentication request")
  o.append ("Accept the authentication request")
  o.append ("""Accept and allow future authentication requests
          from """ + requestor_trans + """
          to """ + fqdn)
  o.append ("""Accept and allow future authentication requests
          from """ + requestor_trans + """
          to any host matching *.""" + domain)
  o.append ("""Accept and allow all future authentication requests
          from """ + requestor_trans + """
          to any host""")

  return msg, o

def main():
  if len(sys.argv) < 6:
    sys.exit (1)

  global requestor, requestor_trans, request, service
  global cur_key, all_keys
  global fqdn, id, host, domain
  requestor = sys.argv[1]
  request = sys.argv[2]
  service = sys.argv[3]
  cur_key = sys.argv[4]
  all_keys = sys.argv[5:]

  try:
    requestor_trans = trans_from ("@" + requestor.split ("@")[1])
    fqdn, id = request.split (",")
    fqdn = fqdn[1:]
    host, domain = fqdn.split (".", 1)
  except:
    sys.exit (1)

  load_state ()
  check_state ()
  msg, o = setup ()
  ask (msg, o)

if __name__ == '__main__':
  main()
