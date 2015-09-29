/* Test program */

#define DT_REG 9
#define DIR_MODE (S_IRUSR|S_IWUSR|S_IXUSR|\
                  S_IRGRP|S_IWGRP|S_IXGRP|\
                  S_IROTH|S_IWOTH|S_IXOTH)
#define FILE_MODE (S_IRUSR|S_IWUSR|\
                   S_IRGRP|S_IWGRP|\
                   S_IROTH|S_IWOTH)
#include "arpc.h"
#include "sfscd_prot.h"
#include "uvfs_prot.h"
#include "uvfs.h"

/* Vnode types.  VNON means no type. */
enum vtype { VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO, VBAD };

int uvfsfd;
static ptr<axprt> uvfsx;
static ptr<asrv> uvfss;

ptr<axprt_unix> cdx;
static ptr<aclnt> cdc;
static ptr<asrv> cds;

static void
cd_dispatch (struct svccb *sbp)
{
  if (!sbp)
    fatal ("EOF from sfscd\n");
  switch (sbp->proc ()) {
  case SFSCDPROC_NULL:
    sbp->reply (NULL);
    break;
  case SFSCDPROC_MOUNT:
    {
      int fd = cdx->recvfd ();
      close (fd);

      sfscd_mountres res (0);
      res.reply->mntflags = 0;
      uvfs_mount_fh root_fh = 0;
      res.reply->fh.setsize (sizeof (root_fh));
      memcpy (res.reply->fh.base (), &root_fh, sizeof (root_fh));
      cdx->sendfd (uvfsfd, false);
      sbp->reply (&res);
      break;
    }
  default:
    sbp->reject (PROC_UNAVAIL);
    break;
  }
}

static void
uvfs_dispatch (struct svccb *sbp)
{
  if (!sbp)
    fatal ("EOF from uvfs_server\n");

  const authunix_parms *aup = sbp->getaup();
  warn << "Got procedure " << sbp->proc() << " --- ";
  if (aup)
    warn << "UID: " << aup->aup_uid << "; GID: " << aup->aup_gid << "\n";

  switch (sbp->proc ()) {
  case UVFSPROC_ACCESS:
    {
      uvfs_accessargs *argp = sbp->template getarg<uvfs_accessargs> ();
      warn << "Args: fh = " << argp->object << "\n";
      uvfs_accessres res (NFS3_OK);
      sbp->reply (&res);
      break;
    }
  case UVFSPROC_LOOKUP:
    {
      uvfs_diropargs *argp = sbp->template getarg<uvfs_diropargs> ();;
      warn << "Args: filename = \"" << argp->name 
	   << "\" in fh = " << argp->dir << "\n";

      if (argp->name[0] == 'a') {
	uvfs_lookupres res (ENOENT);
	sbp->reply (&res);
      }
      else if (argp->name[0] == 'b') {
	uvfs_lookupres res (0);
	res.resok->object = 100;
	res.resok->obj_attributes.set_present (true);
	res.resok->obj_attributes.attributes->type = NF3DIR; // VDIR
	sbp->reply (&res);
      }
      else if (argp->name[0] == 'c') {
	uvfs_lookupres res (0);
	res.resok->object = 200;
	res.resok->obj_attributes.set_present (true);
	res.resok->obj_attributes.attributes->type = NF3LNK; // VLNK
	sbp->reply (&res);
      }
      else {
	uvfs_lookupres res (0);
	res.resok->object = 42;
	res.resok->obj_attributes.set_present (true);
	res.resok->obj_attributes.attributes->type = NF3REG; // VREG
	sbp->reply (&res);
      }
      break;
    }
  case UVFSPROC_GETATTR:
    {
      uvfs_fh *argp = sbp->template getarg<uvfs_fh> ();
      warn << "Arg: fh = " << *argp << "\n";

      uvfs_attrres res (NFS3_OK); // 0
      res.attributes->type = NF3REG; // VREG
      if (*argp < 100)
	res.attributes->mode = FILE_MODE;
      else
	res.attributes->mode = DIR_MODE;
      res.attributes->nlink = 1;
      res.attributes->uid = 1;
      res.attributes->gid = 1;
      res.attributes->size = 54324;
      res.attributes->rdev.major = 1;
      res.attributes->rdev.minor = 2;
      res.attributes->fileid = 1;
      res.attributes->atime.seconds = 12312311;
      res.attributes->atime.nseconds = 0;
      res.attributes->mtime.seconds = 12312311;
      res.attributes->mtime.nseconds = 0;
      res.attributes->ctime.seconds = 12312311;
      res.attributes->ctime.nseconds = 0;
      sbp->reply (&res);
      break;
    }
  case UVFSPROC_SETATTR:
    {
      uvfs_setattrargs *argp = sbp->template getarg<uvfs_setattrargs> ();
      warn << "Arg: fh = " << argp->file << "\n";
      uvfs_wccstat res (NFS3_OK); // 0
      sbp->reply (&res);
      break;
    }
  case UVFSPROC_INACTIVE:
    {
      uvfs_fh *argp = sbp->template getarg<uvfs_fh> ();
      warn << "Arg: fh = " << *argp << "\n";
      uvfsstat res = 0;
      sbp->reply (&res);
      break;
    }
  case UVFSPROC_READDIR:
    {
      uvfs_readdirargs *argp = sbp->template getarg<uvfs_readdirargs> ();
      warn << "Args: fh = " << argp->dir
	   << "; count = " << argp->count
	   << "; cookie = " << argp->cookie[0] << argp->cookie[1]
	   << argp->cookie[2] << argp->cookie[3]
	   << "\n";
      uvfs_readdirres res (0);
      // assume for now that the dir entry fits into count # of bytes
      int totalbytes = 0;
      if (argp->cookie[0] == 0) {
	res.reply->entries.setsize(2);
	for (int i = 0; i < 2; i++) {
	  res.reply->entries[i].fileid = 88+i;
	  res.reply->entries[i].type = DT_REG;
	  res.reply->entries[i].cookie[0] = 5+i;
	  res.reply->entries[i].cookie[1] = 5+i;
	  res.reply->entries[i].cookie[2] = 5+i;
	  res.reply->entries[i].cookie[3] = 5+i;
	  res.reply->entries[i].name = "hello";
	  totalbytes += sizeof(res.reply->entries[i])
	    + res.reply->entries[i].name.len() + 1;
	  warn << "Totalbytes = " << totalbytes << "\n";
	}
      }
      else {
	res.reply->entries.setsize(0);
      }
      sbp->reply (&res);
      break;
    }
  case UVFSPROC_READ:
    {
      uvfs_readargs *argp = sbp->template getarg<uvfs_readargs> ();
      warn << "Args: fh = " << argp->file
	   << "; offset = " << argp->offset 
	   << "; count = " << argp->count << "\n";
      uvfs_readres res (NFS3_OK); // UVFS_STAT
      if (argp->offset >= 3) {
	res.resok->eof = TRUE;
      } 
      else {
	res.resok->eof = FALSE;
	res.resok->data.setsize(3);
	res.resok->data[0] = 'a';
	res.resok->data[1] = 'b';
	res.resok->data[2] = 'c';
      }
      sbp->reply (&res);
      break;
    }
  case UVFSPROC_WRITE:
    {
      uvfs_writeargs *argp = sbp->template getarg<uvfs_writeargs> ();
      warn << "Args: fh = " << argp->file
	   << "; offset = " << argp->offset 
	   << "; count = " << argp->count
	   << "; data = ";
      for (uint i = 0; i < argp->data.size(); i++) {
	warn << argp->data[i];
      }
      warn << "\n";
      uvfs_writeres res (NFS3_OK); // 0
      sbp->reply (&res);
      break;
    }
  case UVFSPROC_REMOVE:
    {
      uvfs_diropargs *argp = sbp->template getarg<uvfs_diropargs> ();;
      warn << "Args: filename = \"" << argp->name 
	   << "\" in fh = " << argp->dir << "\n";
      uvfs_wccstat res (NFS3_OK);
      sbp->reply (&res);
      break;
    }    
  case UVFSPROC_RMDIR:
    {
      uvfs_diropargs *argp = sbp->template getarg<uvfs_diropargs> ();;
      warn << "Args: filename = \"" << argp->name 
	   << "\" in fh = " << argp->dir << "\n";
      uvfs_wccstat res (NFS3_OK);
      sbp->reply (&res);
      break;
    }    
  case UVFSPROC_MKDIR:
    {
      uvfs_mkdirargs *argp = sbp->template getarg<uvfs_mkdirargs> ();;
      warn << "Args: filename = \"" << argp->where.name 
	   << "\" in fh = " << argp->where.dir << "\n";
      uvfs_diropres res = 0;
      res.resok->file.set_present (true);
      *res.resok->file.handle = 653;
      res.resok->attributes.set_present (true);
      res.resok->attributes.attributes->type = NF3DIR; // VDIR
      res.resok->attributes.attributes->mode = DIR_MODE;
      sbp->reply (&res);
      break;
    }    
  case UVFSPROC_RENAME:
    {
      uvfs_renameargs *argp = sbp->template getarg<uvfs_renameargs> ();;
      warn << "Args: fromfilename = \"" << argp->from.name 
	   << "\" in fromfh = " << argp->from.dir
	   << "; tofilename = \"" << argp->to.name 
	   << "\" in tofh = " << argp->to.dir << "\n";
      uvfs_renameres res (NFS3_OK);
      sbp->reply (&res);
      break;
    }    
  case UVFSPROC_CREATE:
    {
      uvfs_createargs *argp = sbp->template getarg<uvfs_createargs> ();;
      warn << "Args: filename = \"" << argp->where.name 
	   << "\" in fh = " << argp->where.dir << "\n";
      uvfs_diropres res = 0;
      res.resok->file.set_present (true);
      *res.resok->file.handle = 23;
      res.resok->attributes.set_present (true);
      res.resok->attributes.attributes->type = NF3REG; // VREG
      res.resok->attributes.attributes->mode = FILE_MODE;
      sbp->reply (&res);
      break;
    }    
  case UVFSPROC_READLINK:
    {
      uvfs_fh *argp = sbp->template getarg<uvfs_fh> ();
      warn << "Arg: fh = " << *argp << "\n";
      uvfs_readlinkres res (NFS3_OK); // 0
      res.resok->data = "fabcd";
      sbp->reply (&res);
      break;
    }
  case UVFSPROC_OPEN:
    {
      uvfs_fh *argp = sbp->template getarg<uvfs_fh> ();
      warn << "Arg: fh = " << *argp << "\n";
      uvfsstat res = 0;
      sbp->reply (&res);
      break;
    }
  case UVFSPROC_CLOSE:
    {
      uvfs_fh *argp = sbp->template getarg<uvfs_fh> ();
      warn << "Arg: fh = " << *argp << "\n";
      uvfsstat res = 0;
      sbp->reply (&res);
      break;
    }
  case UVFSPROC_COMMIT:
    {
      uvfs_commitargs *argp = sbp->template getarg<uvfs_commitargs> ();
      warn << "Args: fh = " << argp->file
	   << "; offset = " << argp->offset
	   << "; count = " << argp->count << "\n";
      uvfs_commitres res (NFS3_OK);
      sbp->reply (&res);
      break;
    }
  case UVFSPROC_STATFS:
    {
      uvfs_fh *argp = sbp->template getarg<uvfs_fh> ();
      warn << "Arg: fh = " << *argp << "\n";
      uvfs_statfsres res (NFS3_OK);
      res.resok->tbytes = 1024333;
      res.resok->fbytes = 512;
      res.resok->abytes = 12345;
      res.resok->tfiles = 8434;
      res.resok->ffiles = 663;
      res.resok->afiles = 63;
      sbp->reply (&res);
      break;
    }
  case UVFSPROC_LINK:
    {
      uvfs_linkargs *argp = sbp->template getarg<uvfs_linkargs> ();
      warn << "Args: fromfh = " << argp->from 
	   << "; tofilename = \"" << argp->to.name 
	   << "\" in tofh = " << argp->to.dir << "\n";
      uvfs_linkres res (NFS3_OK);
      sbp->reply (&res);
      break;
    }
  case UVFSPROC_SYMLINK:
    {
      uvfs_symlinkargs *argp = sbp->template getarg<uvfs_symlinkargs> ();
      warn << "Args: fromfilename = \"" << argp->where.name
	   << "\"; in fromfh = " << argp->where.dir
	   << "; topathname = \"" << argp->symlink.symlink_data
	   << "\"\n";
      uvfs_diropres res (0);
      sbp->reply (&res);
      break;
    }
  default:
    sbp->reject (PROC_UNAVAIL);
    break;
  }
}

int
main (int argc, char **argv)
{
  setprogname (argv[0]);

  if (argc != 1)
    fatal ("usage: %s\n", progname.cstr ());

  uvfsfd = open ("/dev/uvfs0", O_RDWR);

  if (uvfsfd < 0)
    fatal ("/dev/uvfs0: %m\n");

  if (!(cdx = axprt_unix_stdin ())
      || !(cds = asrv::alloc (cdx, sfscd_program_1, wrap (cd_dispatch)))
      || !(cdc = aclnt::alloc (cdx, sfscdcb_program_1)))
    exit (1);

  if (!(uvfsx = axprt_stream::alloc (uvfsfd))
      || !(uvfss = asrv::alloc (uvfsx, uvfsprog_1, wrap (uvfs_dispatch))))
    exit (1);

  amain ();
}
