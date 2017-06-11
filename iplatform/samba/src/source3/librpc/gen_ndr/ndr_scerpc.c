/* parser auto-generated by pidl */

#include "includes.h"
#include "librpc/gen_ndr/ndr_scerpc.h"

static enum ndr_err_code ndr_push_scerpc_Unknown0(struct ndr_push *ndr, int flags, const struct scerpc_Unknown0 *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_push_WERROR(ndr, NDR_SCALARS, r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_scerpc_Unknown0(struct ndr_pull *ndr, int flags, struct scerpc_Unknown0 *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_pull_WERROR(ndr, NDR_SCALARS, &r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_scerpc_Unknown0(struct ndr_print *ndr, const char *name, int flags, const struct scerpc_Unknown0 *r)
{
	ndr_print_struct(ndr, name, "scerpc_Unknown0");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "scerpc_Unknown0");
		ndr->depth++;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		ndr_print_struct(ndr, "out", "scerpc_Unknown0");
		ndr->depth++;
		ndr_print_WERROR(ndr, "result", r->out.result);
		ndr->depth--;
	}
	ndr->depth--;
}

static const struct ndr_interface_call scerpc_calls[] = {
	{
		"scerpc_Unknown0",
		sizeof(struct scerpc_Unknown0),
		(ndr_push_flags_fn_t) ndr_push_scerpc_Unknown0,
		(ndr_pull_flags_fn_t) ndr_pull_scerpc_Unknown0,
		(ndr_print_function_t) ndr_print_disabled,
		{ 0, NULL },
		{ 0, NULL },
	},
	{ NULL, 0, NULL, NULL, NULL }
};

static const char * const scerpc_endpoint_strings[] = {
	"ncacn_np:[\\pipe\\scerpc]", 
};

static const struct ndr_interface_string_array scerpc_endpoints = {
	.count	= 1,
	.names	= scerpc_endpoint_strings
};

static const char * const scerpc_authservice_strings[] = {
	"host", 
};

static const struct ndr_interface_string_array scerpc_authservices = {
	.count	= 1,
	.names	= scerpc_authservice_strings
};


const struct ndr_interface_table ndr_table_scerpc = {
	.name		= "scerpc",
	.syntax_id	= {
		{0x93149ca2,0x973b,0x11d1,{0x8c,0x39},{0x00,0xc0,0x4f,0xb9,0x84,0xf9}},
		NDR_SCERPC_VERSION
	},
	.helpstring	= NDR_SCERPC_HELPSTRING,
	.num_calls	= 1,
	.calls		= scerpc_calls,
	.endpoints	= &scerpc_endpoints,
	.authservices	= &scerpc_authservices
};

