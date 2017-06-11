/* parser auto-generated by pidl */

#include "includes.h"
#include "librpc/gen_ndr/ndr_policyagent.h"

static enum ndr_err_code ndr_push_policyagent_Dummy(struct ndr_push *ndr, int flags, const struct policyagent_Dummy *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_push_WERROR(ndr, NDR_SCALARS, r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_policyagent_Dummy(struct ndr_pull *ndr, int flags, struct policyagent_Dummy *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_pull_WERROR(ndr, NDR_SCALARS, &r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_policyagent_Dummy(struct ndr_print *ndr, const char *name, int flags, const struct policyagent_Dummy *r)
{
	ndr_print_struct(ndr, name, "policyagent_Dummy");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "policyagent_Dummy");
		ndr->depth++;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		ndr_print_struct(ndr, "out", "policyagent_Dummy");
		ndr->depth++;
		ndr_print_WERROR(ndr, "result", r->out.result);
		ndr->depth--;
	}
	ndr->depth--;
}

static const struct ndr_interface_call policyagent_calls[] = {
	{
		"policyagent_Dummy",
		sizeof(struct policyagent_Dummy),
		(ndr_push_flags_fn_t) ndr_push_policyagent_Dummy,
		(ndr_pull_flags_fn_t) ndr_pull_policyagent_Dummy,
		(ndr_print_function_t) ndr_print_disabled,
		{ 0, NULL },
		{ 0, NULL },
	},
	{ NULL, 0, NULL, NULL, NULL }
};

static const char * const policyagent_endpoint_strings[] = {
	"ncacn_np:[\\pipe\\policyagent]", 
};

static const struct ndr_interface_string_array policyagent_endpoints = {
	.count	= 1,
	.names	= policyagent_endpoint_strings
};

static const char * const policyagent_authservice_strings[] = {
	"host", 
};

static const struct ndr_interface_string_array policyagent_authservices = {
	.count	= 1,
	.names	= policyagent_authservice_strings
};


const struct ndr_interface_table ndr_table_policyagent = {
	.name		= "policyagent",
	.syntax_id	= {
		{0xd335b8f6,0xcb31,0x11d0,{0xb0,0xf9},{0x00,0x60,0x97,0xba,0x4e,0x54}},
		NDR_POLICYAGENT_VERSION
	},
	.helpstring	= NDR_POLICYAGENT_HELPSTRING,
	.num_calls	= 1,
	.calls		= policyagent_calls,
	.endpoints	= &policyagent_endpoints,
	.authservices	= &policyagent_authservices
};

