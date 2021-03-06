/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "uvfs_prot.h"
#include "nfs3exp_prot.h"

bool_t
xdr_uvfs_fh(XDR *xdrs, uvfs_fh *objp)
{

	 register int32_t *buf;

	 if (!xdr_u_int32_t(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_fattr(XDR *xdrs, uvfs_fattr *objp)
{

	 register int32_t *buf;

	 if (!xdr_ex_fattr3(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_attrres(XDR *xdrs, uvfs_attrres *objp)
{

	 register int32_t *buf;

	 if (!xdr_ex_getattr3res(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_wccstat(XDR *xdrs, uvfs_wccstat *objp)
{

	 register int32_t *buf;

	 if (!xdr_ex_wccstat3(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_accessres(XDR *xdrs, uvfs_accessres *objp)
{

	 register int32_t *buf;

	 if (!xdr_ex_access3res(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_readlinkres(XDR *xdrs, uvfs_readlinkres *objp)
{

	 register int32_t *buf;

	 if (!xdr_ex_readlink3res(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_readres(XDR *xdrs, uvfs_readres *objp)
{

	 register int32_t *buf;

	 if (!xdr_ex_read3res(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_writeres(XDR *xdrs, uvfs_writeres *objp)
{

	 register int32_t *buf;

	 if (!xdr_ex_write3res(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_renameres(XDR *xdrs, uvfs_renameres *objp)
{

	 register int32_t *buf;

	 if (!xdr_ex_rename3res(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_linkres(XDR *xdrs, uvfs_linkres *objp)
{

	 register int32_t *buf;

	 if (!xdr_ex_link3res(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_statfsres(XDR *xdrs, uvfs_statfsres *objp)
{

	 register int32_t *buf;

	 if (!xdr_ex_fsstat3res(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_commitres(XDR *xdrs, uvfs_commitres *objp)
{

	 register int32_t *buf;

	 if (!xdr_ex_commit3res(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_filename(XDR *xdrs, uvfs_filename *objp)
{

	 register int32_t *buf;

	 if (!xdr_filename3(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_pathname(XDR *xdrs, uvfs_pathname *objp)
{

	 register int32_t *buf;

	 if (!xdr_nfspath3(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_time(XDR *xdrs, uvfs_time *objp)
{

	 register int32_t *buf;

	 if (!xdr_nfstime3(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_sattr(XDR *xdrs, uvfs_sattr *objp)
{

	 register int32_t *buf;

	 if (!xdr_sattr3(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_guard(XDR *xdrs, uvfs_guard *objp)
{

	 register int32_t *buf;

	 if (!xdr_sattrguard3(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfsstat(XDR *xdrs, uvfsstat *objp)
{

	 register int32_t *buf;

	 if (!xdr_int(xdrs, objp)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_readdirargs(XDR *xdrs, uvfs_readdirargs *objp)
{

	 register int32_t *buf;

	 if (!xdr_uvfs_fh(xdrs, &objp->dir)) {
		 return (FALSE);
	 }
	 if (!xdr_u_int64_t(xdrs, &objp->cookie)) {
		 return (FALSE);
	 }
	 if (!xdr_u_int32_t(xdrs, &objp->count)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_direntry(XDR *xdrs, uvfs_direntry *objp)
{

	 register int32_t *buf;

	 if (!xdr_u_int64_t(xdrs, &objp->fileid)) {
		 return (FALSE);
	 }
	 if (!xdr_u_int64_t(xdrs, &objp->cookie)) {
		 return (FALSE);
	 }
	 if (!xdr_u_int32_t(xdrs, &objp->type)) {
		 return (FALSE);
	 }
	 if (!xdr_uvfs_filename(xdrs, &objp->name)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_dirlist(XDR *xdrs, uvfs_dirlist *objp)
{

	 register int32_t *buf;

	 if (!xdr_array(xdrs, (char **)&objp->entries.val, (u_int *)&objp->entries.len, ~0, sizeof(uvfs_direntry), (xdrproc_t)xdr_uvfs_direntry)) {
		 return (FALSE);
	 }
	 if (!xdr_bool(xdrs, &objp->eof)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_readdirres(XDR *xdrs, uvfs_readdirres *objp)
{

	 register int32_t *buf;

	 if (!xdr_uvfsstat(xdrs, &objp->status)) {
		 return (FALSE);
	 }
	switch (objp->status) {
	case 0:
		 if (!xdr_uvfs_dirlist(xdrs, &objp->RPC_UNION_NAME(uvfs_readdirres).reply)) {
			 return (FALSE);
		 }
		break;
	}
	return (TRUE);
}

bool_t
xdr_uvfs_setattrargs(XDR *xdrs, uvfs_setattrargs *objp)
{

	 register int32_t *buf;

	 if (!xdr_uvfs_fh(xdrs, &objp->file)) {
		 return (FALSE);
	 }
	 if (!xdr_uvfs_sattr(xdrs, &objp->attributes)) {
		 return (FALSE);
	 }
	 if (!xdr_uvfs_guard(xdrs, &objp->guard)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_post_op_uvfs_fh(XDR *xdrs, post_op_uvfs_fh *objp)
{

	 register int32_t *buf;

	 if (!xdr_bool(xdrs, &objp->present)) {
		 return (FALSE);
	 }
	switch (objp->present) {
	case TRUE:
		 if (!xdr_uvfs_fh(xdrs, &objp->RPC_UNION_NAME(post_op_uvfs_fh).handle)) {
			 return (FALSE);
		 }
		break;
	case FALSE:
		break;
	default:
		return (FALSE);
	}
	return (TRUE);
}

bool_t
xdr_uvfs_diropargs(XDR *xdrs, uvfs_diropargs *objp)
{

	 register int32_t *buf;

	 if (!xdr_uvfs_fh(xdrs, &objp->dir)) {
		 return (FALSE);
	 }
	 if (!xdr_uvfs_filename(xdrs, &objp->name)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_diropresok(XDR *xdrs, uvfs_diropresok *objp)
{

	 register int32_t *buf;

	 if (!xdr_post_op_uvfs_fh(xdrs, &objp->file)) {
		 return (FALSE);
	 }
	 if (!xdr_ex_post_op_attr(xdrs, &objp->attributes)) {
		 return (FALSE);
	 }
	 if (!xdr_ex_wcc_data(xdrs, &objp->dir_wcc)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_diropres(XDR *xdrs, uvfs_diropres *objp)
{

	 register int32_t *buf;

	 if (!xdr_uvfsstat(xdrs, &objp->status)) {
		 return (FALSE);
	 }
	switch (objp->status) {
	case 0:
		 if (!xdr_uvfs_diropresok(xdrs, &objp->RPC_UNION_NAME(uvfs_diropres).resok)) {
			 return (FALSE);
		 }
		break;
	default:
		 if (!xdr_wcc_data(xdrs, &objp->RPC_UNION_NAME(uvfs_diropres).resfail)) {
			 return (FALSE);
		 }
		break;
	}
	return (TRUE);
}

bool_t
xdr_uvfs_readargs(XDR *xdrs, uvfs_readargs *objp)
{

	 register int32_t *buf;

	 if (!xdr_uvfs_fh(xdrs, &objp->file)) {
		 return (FALSE);
	 }
	 if (!xdr_u_int64_t(xdrs, &objp->offset)) {
		 return (FALSE);
	 }
	 if (!xdr_u_int32_t(xdrs, &objp->count)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_writeargs(XDR *xdrs, uvfs_writeargs *objp)
{

	 register int32_t *buf;

	 if (!xdr_uvfs_fh(xdrs, &objp->file)) {
		 return (FALSE);
	 }
	 if (!xdr_u_int64_t(xdrs, &objp->offset)) {
		 return (FALSE);
	 }
	 if (!xdr_u_int32_t(xdrs, &objp->count)) {
		 return (FALSE);
	 }
	 if (!xdr_stable_how(xdrs, &objp->stable)) {
		 return (FALSE);
	 }
	 if (!xdr_bytes(xdrs, (char **)&objp->data.val, (u_int *)&objp->data.len, ~0)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_createargs(XDR *xdrs, uvfs_createargs *objp)
{

	 register int32_t *buf;

	 if (!xdr_uvfs_diropargs(xdrs, &objp->where)) {
		 return (FALSE);
	 }
	 if (!xdr_createhow3(xdrs, &objp->how)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_mkdirargs(XDR *xdrs, uvfs_mkdirargs *objp)
{

	 register int32_t *buf;

	 if (!xdr_uvfs_diropargs(xdrs, &objp->where)) {
		 return (FALSE);
	 }
	 if (!xdr_uvfs_sattr(xdrs, &objp->attributes)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_renameargs(XDR *xdrs, uvfs_renameargs *objp)
{

	 register int32_t *buf;

	 if (!xdr_uvfs_diropargs(xdrs, &objp->from)) {
		 return (FALSE);
	 }
	 if (!xdr_uvfs_diropargs(xdrs, &objp->to)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_commitargs(XDR *xdrs, uvfs_commitargs *objp)
{

	 register int32_t *buf;

	 if (!xdr_uvfs_fh(xdrs, &objp->file)) {
		 return (FALSE);
	 }
	 if (!xdr_u_int64_t(xdrs, &objp->offset)) {
		 return (FALSE);
	 }
	 if (!xdr_u_int32_t(xdrs, &objp->count)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_linkargs(XDR *xdrs, uvfs_linkargs *objp)
{

	 register int32_t *buf;

	 if (!xdr_uvfs_fh(xdrs, &objp->from)) {
		 return (FALSE);
	 }
	 if (!xdr_uvfs_diropargs(xdrs, &objp->to)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_symlinkargs(XDR *xdrs, uvfs_symlinkargs *objp)
{

	 register int32_t *buf;

	 if (!xdr_uvfs_diropargs(xdrs, &objp->where)) {
		 return (FALSE);
	 }
	 if (!xdr_symlinkdata3(xdrs, &objp->symlink)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_accessargs(XDR *xdrs, uvfs_accessargs *objp)
{

	 register int32_t *buf;

	 if (!xdr_uvfs_fh(xdrs, &objp->object)) {
		 return (FALSE);
	 }
	 if (!xdr_u_int32_t(xdrs, &objp->access)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_lookupresok(XDR *xdrs, uvfs_lookupresok *objp)
{

	 register int32_t *buf;

	 if (!xdr_uvfs_fh(xdrs, &objp->object)) {
		 return (FALSE);
	 }
	 if (!xdr_ex_post_op_attr(xdrs, &objp->obj_attributes)) {
		 return (FALSE);
	 }
	 if (!xdr_ex_post_op_attr(xdrs, &objp->dir_attributes)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_uvfs_lookupres(XDR *xdrs, uvfs_lookupres *objp)
{

	 register int32_t *buf;

	 if (!xdr_uvfsstat(xdrs, &objp->status)) {
		 return (FALSE);
	 }
	switch (objp->status) {
	case 0:
		 if (!xdr_uvfs_lookupresok(xdrs, &objp->RPC_UNION_NAME(uvfs_lookupres).resok)) {
			 return (FALSE);
		 }
		break;
	default:
		 if (!xdr_ex_post_op_attr(xdrs, &objp->RPC_UNION_NAME(uvfs_lookupres).resfail)) {
			 return (FALSE);
		 }
		break;
	}
	return (TRUE);
}

bool_t
xdr_uvfs_invalidateargs(XDR *xdrs, uvfs_invalidateargs *objp)
{

	 register int32_t *buf;

	 if (!xdr_uvfs_fh(xdrs, &objp->handle)) {
		 return (FALSE);
	 }
	 if (!xdr_ex_post_op_attr(xdrs, &objp->attributes)) {
		 return (FALSE);
	 }
	return (TRUE);
}

const struct rpcgen_table uvfsprog_1_table[] = {
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_null_1_svc),
	(xdrproc_t) xdr_void,		0,
	(xdrproc_t) xdr_void,		0,
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_getattr_1_svc),
	(xdrproc_t) xdr_uvfs_fh,	sizeof ( uvfs_fh ),
	(xdrproc_t) xdr_uvfs_attrres,	sizeof ( uvfs_attrres ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_setattr_1_svc),
	(xdrproc_t) xdr_uvfs_setattrargs,sizeof ( uvfs_setattrargs ),
	(xdrproc_t) xdr_uvfs_wccstat,	sizeof ( uvfs_wccstat ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_lookup_1_svc),
	(xdrproc_t) xdr_uvfs_diropargs,	sizeof ( uvfs_diropargs ),
	(xdrproc_t) xdr_uvfs_lookupres,	sizeof ( uvfs_lookupres ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_access_1_svc),
	(xdrproc_t) xdr_uvfs_accessargs,sizeof ( uvfs_accessargs ),
	(xdrproc_t) xdr_uvfs_accessres,	sizeof ( uvfs_accessres ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_readlink_1_svc),
	(xdrproc_t) xdr_uvfs_fh,	sizeof ( uvfs_fh ),
	(xdrproc_t) xdr_uvfs_readlinkres,sizeof ( uvfs_readlinkres ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_read_1_svc),
	(xdrproc_t) xdr_uvfs_readargs,	sizeof ( uvfs_readargs ),
	(xdrproc_t) xdr_uvfs_readres,	sizeof ( uvfs_readres ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_write_1_svc),
	(xdrproc_t) xdr_uvfs_writeargs,	sizeof ( uvfs_writeargs ),
	(xdrproc_t) xdr_uvfs_writeres,	sizeof ( uvfs_writeres ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_create_1_svc),
	(xdrproc_t) xdr_uvfs_createargs,sizeof ( uvfs_createargs ),
	(xdrproc_t) xdr_uvfs_diropres,	sizeof ( uvfs_diropres ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_mkdir_1_svc),
	(xdrproc_t) xdr_uvfs_mkdirargs,	sizeof ( uvfs_mkdirargs ),
	(xdrproc_t) xdr_uvfs_diropres,	sizeof ( uvfs_diropres ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_symlink_1_svc),
	(xdrproc_t) xdr_uvfs_symlinkargs,sizeof ( uvfs_symlinkargs ),
	(xdrproc_t) xdr_uvfs_diropres,	sizeof ( uvfs_diropres ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_mknod_1_svc),
	(xdrproc_t) xdr_void,		0,
	(xdrproc_t) xdr_void,		0,
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_remove_1_svc),
	(xdrproc_t) xdr_uvfs_diropargs,	sizeof ( uvfs_diropargs ),
	(xdrproc_t) xdr_uvfs_wccstat,	sizeof ( uvfs_wccstat ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_rmdir_1_svc),
	(xdrproc_t) xdr_uvfs_diropargs,	sizeof ( uvfs_diropargs ),
	(xdrproc_t) xdr_uvfs_wccstat,	sizeof ( uvfs_wccstat ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_rename_1_svc),
	(xdrproc_t) xdr_uvfs_renameargs,sizeof ( uvfs_renameargs ),
	(xdrproc_t) xdr_uvfs_renameres,	sizeof ( uvfs_renameres ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_link_1_svc),
	(xdrproc_t) xdr_uvfs_linkargs,	sizeof ( uvfs_linkargs ),
	(xdrproc_t) xdr_uvfs_linkres,	sizeof ( uvfs_linkres ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_readdir_1_svc),
	(xdrproc_t) xdr_uvfs_readdirargs,sizeof ( uvfs_readdirargs ),
	(xdrproc_t) xdr_uvfs_readdirres,sizeof ( uvfs_readdirres ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_readdirplus_1_svc),
	(xdrproc_t) xdr_void,		0,
	(xdrproc_t) xdr_void,		0,
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_statfs_1_svc),
	(xdrproc_t) xdr_uvfs_fh,	sizeof ( uvfs_fh ),
	(xdrproc_t) xdr_uvfs_statfsres,	sizeof ( uvfs_statfsres ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_fsinfo_1_svc),
	(xdrproc_t) xdr_void,		0,
	(xdrproc_t) xdr_void,		0,
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_pathconf_1_svc),
	(xdrproc_t) xdr_void,		0,
	(xdrproc_t) xdr_void,		0,
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_commit_1_svc),
	(xdrproc_t) xdr_uvfs_commitargs,sizeof ( uvfs_commitargs ),
	(xdrproc_t) xdr_uvfs_commitres,	sizeof ( uvfs_commitres ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_open_1_svc),
	(xdrproc_t) xdr_uvfs_fh,	sizeof ( uvfs_fh ),
	(xdrproc_t) xdr_uvfsstat,	sizeof ( uvfsstat ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_close_1_svc),
	(xdrproc_t) xdr_uvfs_fh,	sizeof ( uvfs_fh ),
	(xdrproc_t) xdr_uvfsstat,	sizeof ( uvfsstat ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_inactive_1_svc),
	(xdrproc_t) xdr_uvfs_fh,	sizeof ( uvfs_fh ),
	(xdrproc_t) xdr_uvfsstat,	sizeof ( uvfsstat ),
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfsproc_reclaim_1_svc),
	(xdrproc_t) xdr_uvfs_fh,	sizeof ( uvfs_fh ),
	(xdrproc_t) xdr_uvfsstat,	sizeof ( uvfsstat ),
    },
};
const int uvfsprog_1_nproc =
	sizeof(uvfsprog_1_table)/sizeof(uvfsprog_1_table[0]);
const struct rpc_program uvfsprog_1 = {
	UVFSPROG, 1, uvfsprog_1_table,
	sizeof (uvfsprog_1_table) / sizeof (uvfsprog_1_table[0])
};

const struct rpcgen_table uvfscbprog_1_table[] = {
    {
	(char *(*)())RPCGEN_ACTION(uvfscbproc_null_1_svc),
	(xdrproc_t) xdr_void,		0,
	(xdrproc_t) xdr_void,		0,
    },
    {
	(char *(*)())RPCGEN_ACTION(uvfscbproc_invalidate_1_svc),
	(xdrproc_t) xdr_uvfs_invalidateargs,sizeof ( uvfs_invalidateargs ),
	(xdrproc_t) xdr_void,		0,
    },
};
const int uvfscbprog_1_nproc =
	sizeof(uvfscbprog_1_table)/sizeof(uvfscbprog_1_table[0]);
const struct rpc_program uvfscbprog_1 = {
	UVFSCBPROG, 1, uvfscbprog_1_table,
	sizeof (uvfscbprog_1_table) / sizeof (uvfscbprog_1_table[0])
};

