#include "filesrv.h"

fh_entry::fh_entry (str p, nfs_fh3 f, ex_fattr3 *a, filesrv *fs)
  : path (p), fh (f), fa (*a), fsrv (fs)
{ 
  fd = 0; 
  lastused = time (NULL); 
}

fh_entry::~fh_entry (void)
{ 
  assert (fd <= 0);
}

void
fh_entry::print (void)
{
  strbuf sb;
  rpc_print (sb, fh, 5, NULL, " ");

  warnx << path << " fileid " << fa.fileid << " fd: " << fd << " used " << lastused << " " << sb << "\n"; 
}

void
fh_entry::update_attr (int fd)
{
  struct stat sb;

  if (fstat (fd, &sb) != 0)
      warnx << "fstat failed; weird\n";
  trans_attr (&fa, &sb);
}


void
fh_entry::update_attr (str p)
{
  struct stat sb;

  if (stat (p, &sb) != 0)
      warnx << "fstat failed; weird\n";
  trans_attr (&fa, &sb);
}

int
fh_entry::closefd (void)
{
  if (fd > 0) {
    close (fd);
    fd = 0;
    return 1;
  }
  return 0;
}

filesrv::filesrv (void) 
{
  fhe_n = 0;
  fd_n = 0;
  fhetmo = delaycb (fhe_timer, wrap (this, &filesrv::fhetimeout));
}

void
filesrv::purgefhe (void)
{
  if (fhe_n < fhe_max) return; 

  time_t curtime = time (NULL);
  for (fh_entry *fhe = timeoutlist.first; fhe != 0; 
       fhe = timeoutlist.next (fhe)) {
    if (curtime > fhe->lastused + fhe_expire) {
      warnx << "purgefhe: delete old handle\n";
      remove (fhe);
    }
  }
}

void
filesrv::fhetimeout (void)
{
  purgefhe ();
  purgefd (0);
  fhetmo = delaycb (fhe_timer, wrap (this, &filesrv::fhetimeout));
}

void
filesrv::mk_fh (nfs_fh3 *fh, ex_fattr3 *fa)
{
  // compute a file handle XXX improve
  fh->data.setsize (10);
  bzero (fh->data.base (), 10);
  memcpy (fh->data.base (), &fa->fileid, sizeof (fa->fileid));
}

int
filesrv::closefd (fh_entry *fhe)
{
  assert (fd_n >= 0);
  if (fhe->closefd()) {
    fd_n--;
    return 1;
  } else
    return 0;
}

void
filesrv::purgefd (int force)
{
  time_t curtime = time (NULL);
  for (fh_entry *fhe = timeoutlist.first; fhe != 0; 
         fhe = timeoutlist.next(fhe)) {
    if (force || (curtime > fhe->lastused + fd_expire)) {
      (void ) closefd(fhe);

    }
  }
}

void 
filesrv::printfhe (void)
{
  fh_entry *fhe;

  warnx << "entries:\n";

  //  entries.traverse(&fh_entry::print);

  int i = 0;
  for (fhe = entries.first (); fhe != 0; 
         fhe = entries.next(fhe)) {
    i++;
    fhe->print();
  }

  warnx << "entries #entries: " << i << " timeoutlist:\n";

  i = 0;
  for (fhe = timeoutlist.first; fhe != 0; 
         fhe = timeoutlist.next(fhe)) {
    i++;
    // fhe->print();
  }
  warnx << "timeoutlist #entries: " << i << "\n";
}

int
filesrv::checkfd (void)
{
  if (fd_n < fd_max) 
    return 1;

  purgefd(1);

  if (fd_n < fd_max) {
    return 1;
  } else {
    warnx << "checkfd: ENFILE\n";
    errno = ENFILE;
    return 0;
  }
}

int
filesrv::getfd (fh_entry *fhe, int flags)
{
  // check permissions XXX
  assert (fhe);

  if (!checkfd ()) return -1;

  int fd = open (fhe->path, flags, 0);
  if (fd > 0) {
    fd_n++;
    fhe->setfd(fd);
  }
  return fd;
}

int
filesrv::getfd (str p, int flags, mode_t mode)
{
  if (!checkfd ()) return -1;

  // check permissions XXX
  int fd = open (p, flags, mode);
  if (fd > 0) fd_n++;
  return fd;
}


fh_entry *
filesrv::lookup (nfs_fh3 *fh) 
{ 
  fh_entry *fhe = entries[*fh];
  if (fhe) {
    timeoutlist.remove (fhe);
    fhe->lastused = time (NULL);
    timeoutlist.insert_tail (fhe);
  }
  return fhe;
}

int
filesrv::checkfhe (void)
{
  if (fhe_n < fhe_max)
    return 1;

  warnx << "checkfhe: out of fh entries\n";

  purgefhe();

  if (fhe_n < fhe_max) {
    return 1;
  } else {
    warnx << "checkfhe: EMFILE\n";
    errno = EMFILE;
    return 0;
  }
}

int
filesrv::lookup_attr (str p, ex_fattr3 *fa)
{
  struct stat sb;

  if (lstat (p, &sb) != 0) 
    return 0;
  trans_attr (fa, &sb);
  return 1;
}

fh_entry *
filesrv::lookup_add (str p)
{  
  ex_fattr3 fa;
  nfs_fh3 fh;

  if (!lookup_attr (p, &fa))
      return NULL;
  mk_fh (&fh, &fa);
  fh_entry *fhe = lookup (&fh);
  if (!fhe) {
    if (checkfhe ()) {
      fhe = New fh_entry (p, fh, &fa, this);
      entries.insert (fhe);
      timeoutlist.insert_tail (fhe);
      fhe_n++;
    } else {
      errno = EMFILE;
      return NULL;
    }
  }
  return fhe;
}

void
filesrv::remove (fh_entry *fhe)
{
  timeoutlist.remove (fhe);
  entries.remove (fhe);
  fhe_n--;
  closefd (fhe);
  delete fhe;
}
