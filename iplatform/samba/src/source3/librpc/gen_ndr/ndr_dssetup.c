/* parser auto-generated by pidl */

#include "includes.h"
#include "librpc/gen_ndr/ndr_dssetup.h"

#include "librpc/gen_ndr/ndr_misc.h"
static enum ndr_err_code ndr_push_dssetup_DsRole(struct ndr_push *ndr, int ndr_flags, enum dssetup_DsRole r)
{
	NDR_CHECK(ndr_push_enum_uint1632(ndr, NDR_SCALARS, r));
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRole(struct ndr_pull *ndr, int ndr_flags, enum dssetup_DsRole *r)
{
	uint16_t v;
	NDR_CHECK(ndr_pull_enum_uint1632(ndr, NDR_SCALARS, &v));
	*r = v;
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRole(struct ndr_print *ndr, const char *name, enum dssetup_DsRole r)
{
	const char *val = NULL;

	switch (r) {
		case DS_ROLE_STANDALONE_WORKSTATION: val = "DS_ROLE_STANDALONE_WORKSTATION"; break;
		case DS_ROLE_MEMBER_WORKSTATION: val = "DS_ROLE_MEMBER_WORKSTATION"; break;
		case DS_ROLE_STANDALONE_SERVER: val = "DS_ROLE_STANDALONE_SERVER"; break;
		case DS_ROLE_MEMBER_SERVER: val = "DS_ROLE_MEMBER_SERVER"; break;
		case DS_ROLE_BACKUP_DC: val = "DS_ROLE_BACKUP_DC"; break;
		case DS_ROLE_PRIMARY_DC: val = "DS_ROLE_PRIMARY_DC"; break;
	}
	ndr_print_enum(ndr, name, "ENUM", val, r);
}

static enum ndr_err_code ndr_push_dssetup_DsRoleFlags(struct ndr_push *ndr, int ndr_flags, uint32_t r)
{
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r));
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRoleFlags(struct ndr_pull *ndr, int ndr_flags, uint32_t *r)
{
	uint32_t v;
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &v));
	*r = v;
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRoleFlags(struct ndr_print *ndr, const char *name, uint32_t r)
{
	ndr_print_uint32(ndr, name, r);
	ndr->depth++;
	ndr_print_bitmap_flag(ndr, sizeof(uint32_t), "DS_ROLE_PRIMARY_DS_RUNNING", DS_ROLE_PRIMARY_DS_RUNNING, r);
	ndr_print_bitmap_flag(ndr, sizeof(uint32_t), "DS_ROLE_PRIMARY_DS_MIXED_MODE", DS_ROLE_PRIMARY_DS_MIXED_MODE, r);
	ndr_print_bitmap_flag(ndr, sizeof(uint32_t), "DS_ROLE_UPGRADE_IN_PROGRESS", DS_ROLE_UPGRADE_IN_PROGRESS, r);
	ndr_print_bitmap_flag(ndr, sizeof(uint32_t), "DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT", DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT, r);
	ndr->depth--;
}

static enum ndr_err_code ndr_push_dssetup_DsRolePrimaryDomInfoBasic(struct ndr_push *ndr, int ndr_flags, const struct dssetup_DsRolePrimaryDomInfoBasic *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 5));
		NDR_CHECK(ndr_push_dssetup_DsRole(ndr, NDR_SCALARS, r->role));
		NDR_CHECK(ndr_push_dssetup_DsRoleFlags(ndr, NDR_SCALARS, r->flags));
		NDR_CHECK(ndr_push_unique_ptr(ndr, r->domain));
		NDR_CHECK(ndr_push_unique_ptr(ndr, r->dns_domain));
		NDR_CHECK(ndr_push_unique_ptr(ndr, r->forest));
		NDR_CHECK(ndr_push_GUID(ndr, NDR_SCALARS, &r->domain_guid));
		NDR_CHECK(ndr_push_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->domain) {
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, ndr_charset_length(r->domain, CH_UTF16)));
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, 0));
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, ndr_charset_length(r->domain, CH_UTF16)));
			NDR_CHECK(ndr_push_charset(ndr, NDR_SCALARS, r->domain, ndr_charset_length(r->domain, CH_UTF16), sizeof(uint16_t), CH_UTF16));
		}
		if (r->dns_domain) {
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, ndr_charset_length(r->dns_domain, CH_UTF16)));
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, 0));
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, ndr_charset_length(r->dns_domain, CH_UTF16)));
			NDR_CHECK(ndr_push_charset(ndr, NDR_SCALARS, r->dns_domain, ndr_charset_length(r->dns_domain, CH_UTF16), sizeof(uint16_t), CH_UTF16));
		}
		if (r->forest) {
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, ndr_charset_length(r->forest, CH_UTF16)));
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, 0));
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, ndr_charset_length(r->forest, CH_UTF16)));
			NDR_CHECK(ndr_push_charset(ndr, NDR_SCALARS, r->forest, ndr_charset_length(r->forest, CH_UTF16), sizeof(uint16_t), CH_UTF16));
		}
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRolePrimaryDomInfoBasic(struct ndr_pull *ndr, int ndr_flags, struct dssetup_DsRolePrimaryDomInfoBasic *r)
{
	uint32_t _ptr_domain;
	uint32_t size_domain_1 = 0;
	uint32_t length_domain_1 = 0;
	TALLOC_CTX *_mem_save_domain_0;
	uint32_t _ptr_dns_domain;
	uint32_t size_dns_domain_1 = 0;
	uint32_t length_dns_domain_1 = 0;
	TALLOC_CTX *_mem_save_dns_domain_0;
	uint32_t _ptr_forest;
	uint32_t size_forest_1 = 0;
	uint32_t length_forest_1 = 0;
	TALLOC_CTX *_mem_save_forest_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 5));
		NDR_CHECK(ndr_pull_dssetup_DsRole(ndr, NDR_SCALARS, &r->role));
		NDR_CHECK(ndr_pull_dssetup_DsRoleFlags(ndr, NDR_SCALARS, &r->flags));
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_domain));
		if (_ptr_domain) {
			NDR_PULL_ALLOC(ndr, r->domain);
		} else {
			r->domain = NULL;
		}
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_dns_domain));
		if (_ptr_dns_domain) {
			NDR_PULL_ALLOC(ndr, r->dns_domain);
		} else {
			r->dns_domain = NULL;
		}
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_forest));
		if (_ptr_forest) {
			NDR_PULL_ALLOC(ndr, r->forest);
		} else {
			r->forest = NULL;
		}
		NDR_CHECK(ndr_pull_GUID(ndr, NDR_SCALARS, &r->domain_guid));
		NDR_CHECK(ndr_pull_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->domain) {
			_mem_save_domain_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->domain, 0);
			NDR_CHECK(ndr_pull_array_size(ndr, &r->domain));
			NDR_CHECK(ndr_pull_array_length(ndr, &r->domain));
			size_domain_1 = ndr_get_array_size(ndr, &r->domain);
			length_domain_1 = ndr_get_array_length(ndr, &r->domain);
			if (length_domain_1 > size_domain_1) {
				return ndr_pull_error(ndr, NDR_ERR_ARRAY_SIZE, "Bad array size %u should exceed array length %u", size_domain_1, length_domain_1);
			}
			NDR_CHECK(ndr_check_string_terminator(ndr, length_domain_1, sizeof(uint16_t)));
			NDR_CHECK(ndr_pull_charset(ndr, NDR_SCALARS, &r->domain, length_domain_1, sizeof(uint16_t), CH_UTF16));
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_domain_0, 0);
		}
		if (r->dns_domain) {
			_mem_save_dns_domain_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->dns_domain, 0);
			NDR_CHECK(ndr_pull_array_size(ndr, &r->dns_domain));
			NDR_CHECK(ndr_pull_array_length(ndr, &r->dns_domain));
			size_dns_domain_1 = ndr_get_array_size(ndr, &r->dns_domain);
			length_dns_domain_1 = ndr_get_array_length(ndr, &r->dns_domain);
			if (length_dns_domain_1 > size_dns_domain_1) {
				return ndr_pull_error(ndr, NDR_ERR_ARRAY_SIZE, "Bad array size %u should exceed array length %u", size_dns_domain_1, length_dns_domain_1);
			}
			NDR_CHECK(ndr_check_string_terminator(ndr, length_dns_domain_1, sizeof(uint16_t)));
			NDR_CHECK(ndr_pull_charset(ndr, NDR_SCALARS, &r->dns_domain, length_dns_domain_1, sizeof(uint16_t), CH_UTF16));
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_dns_domain_0, 0);
		}
		if (r->forest) {
			_mem_save_forest_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->forest, 0);
			NDR_CHECK(ndr_pull_array_size(ndr, &r->forest));
			NDR_CHECK(ndr_pull_array_length(ndr, &r->forest));
			size_forest_1 = ndr_get_array_size(ndr, &r->forest);
			length_forest_1 = ndr_get_array_length(ndr, &r->forest);
			if (length_forest_1 > size_forest_1) {
				return ndr_pull_error(ndr, NDR_ERR_ARRAY_SIZE, "Bad array size %u should exceed array length %u", size_forest_1, length_forest_1);
			}
			NDR_CHECK(ndr_check_string_terminator(ndr, length_forest_1, sizeof(uint16_t)));
			NDR_CHECK(ndr_pull_charset(ndr, NDR_SCALARS, &r->forest, length_forest_1, sizeof(uint16_t), CH_UTF16));
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_forest_0, 0);
		}
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRolePrimaryDomInfoBasic(struct ndr_print *ndr, const char *name, const struct dssetup_DsRolePrimaryDomInfoBasic *r)
{
	ndr_print_struct(ndr, name, "dssetup_DsRolePrimaryDomInfoBasic");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	ndr_print_dssetup_DsRole(ndr, "role", r->role);
	ndr_print_dssetup_DsRoleFlags(ndr, "flags", r->flags);
	ndr_print_ptr(ndr, "domain", r->domain);
	ndr->depth++;
	if (r->domain) {
		ndr_print_string(ndr, "domain", r->domain);
	}
	ndr->depth--;
	ndr_print_ptr(ndr, "dns_domain", r->dns_domain);
	ndr->depth++;
	if (r->dns_domain) {
		ndr_print_string(ndr, "dns_domain", r->dns_domain);
	}
	ndr->depth--;
	ndr_print_ptr(ndr, "forest", r->forest);
	ndr->depth++;
	if (r->forest) {
		ndr_print_string(ndr, "forest", r->forest);
	}
	ndr->depth--;
	ndr_print_GUID(ndr, "domain_guid", &r->domain_guid);
	ndr->depth--;
}

static enum ndr_err_code ndr_push_dssetup_DsUpgrade(struct ndr_push *ndr, int ndr_flags, enum dssetup_DsUpgrade r)
{
	NDR_CHECK(ndr_push_enum_uint32(ndr, NDR_SCALARS, r));
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsUpgrade(struct ndr_pull *ndr, int ndr_flags, enum dssetup_DsUpgrade *r)
{
	uint32_t v;
	NDR_CHECK(ndr_pull_enum_uint32(ndr, NDR_SCALARS, &v));
	*r = v;
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsUpgrade(struct ndr_print *ndr, const char *name, enum dssetup_DsUpgrade r)
{
	const char *val = NULL;

	switch (r) {
		case DS_ROLE_NOT_UPGRADING: val = "DS_ROLE_NOT_UPGRADING"; break;
		case DS_ROLE_UPGRADING: val = "DS_ROLE_UPGRADING"; break;
	}
	ndr_print_enum(ndr, name, "ENUM", val, r);
}

static enum ndr_err_code ndr_push_dssetup_DsPrevious(struct ndr_push *ndr, int ndr_flags, enum dssetup_DsPrevious r)
{
	NDR_CHECK(ndr_push_enum_uint1632(ndr, NDR_SCALARS, r));
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsPrevious(struct ndr_pull *ndr, int ndr_flags, enum dssetup_DsPrevious *r)
{
	uint16_t v;
	NDR_CHECK(ndr_pull_enum_uint1632(ndr, NDR_SCALARS, &v));
	*r = v;
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsPrevious(struct ndr_print *ndr, const char *name, enum dssetup_DsPrevious r)
{
	const char *val = NULL;

	switch (r) {
		case DS_ROLE_PREVIOUS_UNKNOWN: val = "DS_ROLE_PREVIOUS_UNKNOWN"; break;
		case DS_ROLE_PREVIOUS_PRIMARY: val = "DS_ROLE_PREVIOUS_PRIMARY"; break;
		case DS_ROLE_PREVIOUS_BACKUP: val = "DS_ROLE_PREVIOUS_BACKUP"; break;
	}
	ndr_print_enum(ndr, name, "ENUM", val, r);
}

static enum ndr_err_code ndr_push_dssetup_DsRoleUpgradeStatus(struct ndr_push *ndr, int ndr_flags, const struct dssetup_DsRoleUpgradeStatus *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_dssetup_DsUpgrade(ndr, NDR_SCALARS, r->upgrading));
		NDR_CHECK(ndr_push_dssetup_DsPrevious(ndr, NDR_SCALARS, r->previous_role));
		NDR_CHECK(ndr_push_trailer_align(ndr, 4));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRoleUpgradeStatus(struct ndr_pull *ndr, int ndr_flags, struct dssetup_DsRoleUpgradeStatus *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_dssetup_DsUpgrade(ndr, NDR_SCALARS, &r->upgrading));
		NDR_CHECK(ndr_pull_dssetup_DsPrevious(ndr, NDR_SCALARS, &r->previous_role));
		NDR_CHECK(ndr_pull_trailer_align(ndr, 4));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRoleUpgradeStatus(struct ndr_print *ndr, const char *name, const struct dssetup_DsRoleUpgradeStatus *r)
{
	ndr_print_struct(ndr, name, "dssetup_DsRoleUpgradeStatus");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	ndr_print_dssetup_DsUpgrade(ndr, "upgrading", r->upgrading);
	ndr_print_dssetup_DsPrevious(ndr, "previous_role", r->previous_role);
	ndr->depth--;
}

static enum ndr_err_code ndr_push_dssetup_DsRoleOp(struct ndr_push *ndr, int ndr_flags, enum dssetup_DsRoleOp r)
{
	NDR_CHECK(ndr_push_enum_uint1632(ndr, NDR_SCALARS, r));
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRoleOp(struct ndr_pull *ndr, int ndr_flags, enum dssetup_DsRoleOp *r)
{
	uint16_t v;
	NDR_CHECK(ndr_pull_enum_uint1632(ndr, NDR_SCALARS, &v));
	*r = v;
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRoleOp(struct ndr_print *ndr, const char *name, enum dssetup_DsRoleOp r)
{
	const char *val = NULL;

	switch (r) {
		case DS_ROLE_OP_IDLE: val = "DS_ROLE_OP_IDLE"; break;
		case DS_ROLE_OP_ACTIVE: val = "DS_ROLE_OP_ACTIVE"; break;
		case DS_ROLE_OP_NEEDS_REBOOT: val = "DS_ROLE_OP_NEEDS_REBOOT"; break;
	}
	ndr_print_enum(ndr, name, "ENUM", val, r);
}

static enum ndr_err_code ndr_push_dssetup_DsRoleOpStatus(struct ndr_push *ndr, int ndr_flags, const struct dssetup_DsRoleOpStatus *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 3));
		NDR_CHECK(ndr_push_dssetup_DsRoleOp(ndr, NDR_SCALARS, r->status));
		NDR_CHECK(ndr_push_trailer_align(ndr, 3));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRoleOpStatus(struct ndr_pull *ndr, int ndr_flags, struct dssetup_DsRoleOpStatus *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 3));
		NDR_CHECK(ndr_pull_dssetup_DsRoleOp(ndr, NDR_SCALARS, &r->status));
		NDR_CHECK(ndr_pull_trailer_align(ndr, 3));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRoleOpStatus(struct ndr_print *ndr, const char *name, const struct dssetup_DsRoleOpStatus *r)
{
	ndr_print_struct(ndr, name, "dssetup_DsRoleOpStatus");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	ndr_print_dssetup_DsRoleOp(ndr, "status", r->status);
	ndr->depth--;
}

static enum ndr_err_code ndr_push_dssetup_DsRoleInfoLevel(struct ndr_push *ndr, int ndr_flags, enum dssetup_DsRoleInfoLevel r)
{
	NDR_CHECK(ndr_push_enum_uint1632(ndr, NDR_SCALARS, r));
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRoleInfoLevel(struct ndr_pull *ndr, int ndr_flags, enum dssetup_DsRoleInfoLevel *r)
{
	uint16_t v;
	NDR_CHECK(ndr_pull_enum_uint1632(ndr, NDR_SCALARS, &v));
	*r = v;
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRoleInfoLevel(struct ndr_print *ndr, const char *name, enum dssetup_DsRoleInfoLevel r)
{
	const char *val = NULL;

	switch (r) {
		case DS_ROLE_BASIC_INFORMATION: val = "DS_ROLE_BASIC_INFORMATION"; break;
		case DS_ROLE_UPGRADE_STATUS: val = "DS_ROLE_UPGRADE_STATUS"; break;
		case DS_ROLE_OP_STATUS: val = "DS_ROLE_OP_STATUS"; break;
	}
	ndr_print_enum(ndr, name, "ENUM", val, r);
}

static enum ndr_err_code ndr_push_dssetup_DsRoleInfo(struct ndr_push *ndr, int ndr_flags, const union dssetup_DsRoleInfo *r)
{
	if (ndr_flags & NDR_SCALARS) {
		uint32_t level = ndr_push_get_switch_value(ndr, r);
		NDR_CHECK(ndr_push_union_align(ndr, 5));
		NDR_CHECK(ndr_push_dssetup_DsRoleInfoLevel(ndr, NDR_SCALARS, level));
		NDR_CHECK(ndr_push_union_align(ndr, 5));
		switch (level) {
			case DS_ROLE_BASIC_INFORMATION: {
				NDR_CHECK(ndr_push_dssetup_DsRolePrimaryDomInfoBasic(ndr, NDR_SCALARS, &r->basic));
			break; }

			case DS_ROLE_UPGRADE_STATUS: {
				NDR_CHECK(ndr_push_dssetup_DsRoleUpgradeStatus(ndr, NDR_SCALARS, &r->upgrade));
			break; }

			case DS_ROLE_OP_STATUS: {
				NDR_CHECK(ndr_push_dssetup_DsRoleOpStatus(ndr, NDR_SCALARS, &r->opstatus));
			break; }

			default:
				return ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u at %s", level, __location__);
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		uint32_t level = ndr_push_get_switch_value(ndr, r);
		switch (level) {
			case DS_ROLE_BASIC_INFORMATION:
				NDR_CHECK(ndr_push_dssetup_DsRolePrimaryDomInfoBasic(ndr, NDR_BUFFERS, &r->basic));
			break;

			case DS_ROLE_UPGRADE_STATUS:
			break;

			case DS_ROLE_OP_STATUS:
			break;

			default:
				return ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u at %s", level, __location__);
		}
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRoleInfo(struct ndr_pull *ndr, int ndr_flags, union dssetup_DsRoleInfo *r)
{
	uint32_t level;
	uint16_t _level;
	level = ndr_pull_get_switch_value(ndr, r);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_union_align(ndr, 5));
		NDR_CHECK(ndr_pull_uint1632(ndr, NDR_SCALARS, &_level));
		if (_level != level) {
			return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u for r at %s", _level, __location__);
		}
		NDR_CHECK(ndr_pull_union_align(ndr, 5));
		switch (level) {
			case DS_ROLE_BASIC_INFORMATION: {
				NDR_CHECK(ndr_pull_dssetup_DsRolePrimaryDomInfoBasic(ndr, NDR_SCALARS, &r->basic));
			break; }

			case DS_ROLE_UPGRADE_STATUS: {
				NDR_CHECK(ndr_pull_dssetup_DsRoleUpgradeStatus(ndr, NDR_SCALARS, &r->upgrade));
			break; }

			case DS_ROLE_OP_STATUS: {
				NDR_CHECK(ndr_pull_dssetup_DsRoleOpStatus(ndr, NDR_SCALARS, &r->opstatus));
			break; }

			default:
				return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u at %s", level, __location__);
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		switch (level) {
			case DS_ROLE_BASIC_INFORMATION:
				NDR_CHECK(ndr_pull_dssetup_DsRolePrimaryDomInfoBasic(ndr, NDR_BUFFERS, &r->basic));
			break;

			case DS_ROLE_UPGRADE_STATUS:
			break;

			case DS_ROLE_OP_STATUS:
			break;

			default:
				return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u at %s", level, __location__);
		}
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRoleInfo(struct ndr_print *ndr, const char *name, const union dssetup_DsRoleInfo *r)
{
	uint32_t level;
	level = ndr_print_get_switch_value(ndr, r);
	ndr_print_union(ndr, name, level, "dssetup_DsRoleInfo");
	switch (level) {
		case DS_ROLE_BASIC_INFORMATION:
			ndr_print_dssetup_DsRolePrimaryDomInfoBasic(ndr, "basic", &r->basic);
		break;

		case DS_ROLE_UPGRADE_STATUS:
			ndr_print_dssetup_DsRoleUpgradeStatus(ndr, "upgrade", &r->upgrade);
		break;

		case DS_ROLE_OP_STATUS:
			ndr_print_dssetup_DsRoleOpStatus(ndr, "opstatus", &r->opstatus);
		break;

		default:
			ndr_print_bad_level(ndr, name, level);
	}
}

static enum ndr_err_code ndr_push_dssetup_DsRoleGetPrimaryDomainInformation(struct ndr_push *ndr, int flags, const struct dssetup_DsRoleGetPrimaryDomainInformation *r)
{
	if (flags & NDR_IN) {
		NDR_CHECK(ndr_push_dssetup_DsRoleInfoLevel(ndr, NDR_SCALARS, r->in.level));
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_push_unique_ptr(ndr, r->out.info));
		if (r->out.info) {
			NDR_CHECK(ndr_push_set_switch_value(ndr, r->out.info, r->in.level));
			NDR_CHECK(ndr_push_dssetup_DsRoleInfo(ndr, NDR_SCALARS|NDR_BUFFERS, r->out.info));
		}
		NDR_CHECK(ndr_push_WERROR(ndr, NDR_SCALARS, r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRoleGetPrimaryDomainInformation(struct ndr_pull *ndr, int flags, struct dssetup_DsRoleGetPrimaryDomainInformation *r)
{
	uint32_t _ptr_info;
	TALLOC_CTX *_mem_save_info_0;
	if (flags & NDR_IN) {
		ZERO_STRUCT(r->out);

		NDR_CHECK(ndr_pull_dssetup_DsRoleInfoLevel(ndr, NDR_SCALARS, &r->in.level));
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_info));
		if (_ptr_info) {
			NDR_PULL_ALLOC(ndr, r->out.info);
		} else {
			r->out.info = NULL;
		}
		if (r->out.info) {
			_mem_save_info_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->out.info, 0);
			NDR_CHECK(ndr_pull_set_switch_value(ndr, r->out.info, r->in.level));
			NDR_CHECK(ndr_pull_dssetup_DsRoleInfo(ndr, NDR_SCALARS|NDR_BUFFERS, r->out.info));
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_info_0, 0);
		}
		NDR_CHECK(ndr_pull_WERROR(ndr, NDR_SCALARS, &r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRoleGetPrimaryDomainInformation(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleGetPrimaryDomainInformation *r)
{
	ndr_print_struct(ndr, name, "dssetup_DsRoleGetPrimaryDomainInformation");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "dssetup_DsRoleGetPrimaryDomainInformation");
		ndr->depth++;
		ndr_print_dssetup_DsRoleInfoLevel(ndr, "level", r->in.level);
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		ndr_print_struct(ndr, "out", "dssetup_DsRoleGetPrimaryDomainInformation");
		ndr->depth++;
		ndr_print_ptr(ndr, "info", r->out.info);
		ndr->depth++;
		if (r->out.info) {
			ndr_print_set_switch_value(ndr, r->out.info, r->in.level);
			ndr_print_dssetup_DsRoleInfo(ndr, "info", r->out.info);
		}
		ndr->depth--;
		ndr_print_WERROR(ndr, "result", r->out.result);
		ndr->depth--;
	}
	ndr->depth--;
}

static enum ndr_err_code ndr_push_dssetup_DsRoleDnsNameToFlatName(struct ndr_push *ndr, int flags, const struct dssetup_DsRoleDnsNameToFlatName *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_push_WERROR(ndr, NDR_SCALARS, r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRoleDnsNameToFlatName(struct ndr_pull *ndr, int flags, struct dssetup_DsRoleDnsNameToFlatName *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_pull_WERROR(ndr, NDR_SCALARS, &r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRoleDnsNameToFlatName(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleDnsNameToFlatName *r)
{
	ndr_print_struct(ndr, name, "dssetup_DsRoleDnsNameToFlatName");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "dssetup_DsRoleDnsNameToFlatName");
		ndr->depth++;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		ndr_print_struct(ndr, "out", "dssetup_DsRoleDnsNameToFlatName");
		ndr->depth++;
		ndr_print_WERROR(ndr, "result", r->out.result);
		ndr->depth--;
	}
	ndr->depth--;
}

static enum ndr_err_code ndr_push_dssetup_DsRoleDcAsDc(struct ndr_push *ndr, int flags, const struct dssetup_DsRoleDcAsDc *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_push_WERROR(ndr, NDR_SCALARS, r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRoleDcAsDc(struct ndr_pull *ndr, int flags, struct dssetup_DsRoleDcAsDc *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_pull_WERROR(ndr, NDR_SCALARS, &r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRoleDcAsDc(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleDcAsDc *r)
{
	ndr_print_struct(ndr, name, "dssetup_DsRoleDcAsDc");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "dssetup_DsRoleDcAsDc");
		ndr->depth++;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		ndr_print_struct(ndr, "out", "dssetup_DsRoleDcAsDc");
		ndr->depth++;
		ndr_print_WERROR(ndr, "result", r->out.result);
		ndr->depth--;
	}
	ndr->depth--;
}

static enum ndr_err_code ndr_push_dssetup_DsRoleDcAsReplica(struct ndr_push *ndr, int flags, const struct dssetup_DsRoleDcAsReplica *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_push_WERROR(ndr, NDR_SCALARS, r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRoleDcAsReplica(struct ndr_pull *ndr, int flags, struct dssetup_DsRoleDcAsReplica *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_pull_WERROR(ndr, NDR_SCALARS, &r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRoleDcAsReplica(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleDcAsReplica *r)
{
	ndr_print_struct(ndr, name, "dssetup_DsRoleDcAsReplica");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "dssetup_DsRoleDcAsReplica");
		ndr->depth++;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		ndr_print_struct(ndr, "out", "dssetup_DsRoleDcAsReplica");
		ndr->depth++;
		ndr_print_WERROR(ndr, "result", r->out.result);
		ndr->depth--;
	}
	ndr->depth--;
}

static enum ndr_err_code ndr_push_dssetup_DsRoleDemoteDc(struct ndr_push *ndr, int flags, const struct dssetup_DsRoleDemoteDc *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_push_WERROR(ndr, NDR_SCALARS, r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRoleDemoteDc(struct ndr_pull *ndr, int flags, struct dssetup_DsRoleDemoteDc *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_pull_WERROR(ndr, NDR_SCALARS, &r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRoleDemoteDc(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleDemoteDc *r)
{
	ndr_print_struct(ndr, name, "dssetup_DsRoleDemoteDc");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "dssetup_DsRoleDemoteDc");
		ndr->depth++;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		ndr_print_struct(ndr, "out", "dssetup_DsRoleDemoteDc");
		ndr->depth++;
		ndr_print_WERROR(ndr, "result", r->out.result);
		ndr->depth--;
	}
	ndr->depth--;
}

static enum ndr_err_code ndr_push_dssetup_DsRoleGetDcOperationProgress(struct ndr_push *ndr, int flags, const struct dssetup_DsRoleGetDcOperationProgress *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_push_WERROR(ndr, NDR_SCALARS, r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRoleGetDcOperationProgress(struct ndr_pull *ndr, int flags, struct dssetup_DsRoleGetDcOperationProgress *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_pull_WERROR(ndr, NDR_SCALARS, &r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRoleGetDcOperationProgress(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleGetDcOperationProgress *r)
{
	ndr_print_struct(ndr, name, "dssetup_DsRoleGetDcOperationProgress");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "dssetup_DsRoleGetDcOperationProgress");
		ndr->depth++;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		ndr_print_struct(ndr, "out", "dssetup_DsRoleGetDcOperationProgress");
		ndr->depth++;
		ndr_print_WERROR(ndr, "result", r->out.result);
		ndr->depth--;
	}
	ndr->depth--;
}

static enum ndr_err_code ndr_push_dssetup_DsRoleGetDcOperationResults(struct ndr_push *ndr, int flags, const struct dssetup_DsRoleGetDcOperationResults *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_push_WERROR(ndr, NDR_SCALARS, r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRoleGetDcOperationResults(struct ndr_pull *ndr, int flags, struct dssetup_DsRoleGetDcOperationResults *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_pull_WERROR(ndr, NDR_SCALARS, &r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRoleGetDcOperationResults(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleGetDcOperationResults *r)
{
	ndr_print_struct(ndr, name, "dssetup_DsRoleGetDcOperationResults");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "dssetup_DsRoleGetDcOperationResults");
		ndr->depth++;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		ndr_print_struct(ndr, "out", "dssetup_DsRoleGetDcOperationResults");
		ndr->depth++;
		ndr_print_WERROR(ndr, "result", r->out.result);
		ndr->depth--;
	}
	ndr->depth--;
}

static enum ndr_err_code ndr_push_dssetup_DsRoleCancel(struct ndr_push *ndr, int flags, const struct dssetup_DsRoleCancel *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_push_WERROR(ndr, NDR_SCALARS, r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRoleCancel(struct ndr_pull *ndr, int flags, struct dssetup_DsRoleCancel *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_pull_WERROR(ndr, NDR_SCALARS, &r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRoleCancel(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleCancel *r)
{
	ndr_print_struct(ndr, name, "dssetup_DsRoleCancel");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "dssetup_DsRoleCancel");
		ndr->depth++;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		ndr_print_struct(ndr, "out", "dssetup_DsRoleCancel");
		ndr->depth++;
		ndr_print_WERROR(ndr, "result", r->out.result);
		ndr->depth--;
	}
	ndr->depth--;
}

static enum ndr_err_code ndr_push_dssetup_DsRoleServerSaveStateForUpgrade(struct ndr_push *ndr, int flags, const struct dssetup_DsRoleServerSaveStateForUpgrade *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_push_WERROR(ndr, NDR_SCALARS, r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRoleServerSaveStateForUpgrade(struct ndr_pull *ndr, int flags, struct dssetup_DsRoleServerSaveStateForUpgrade *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_pull_WERROR(ndr, NDR_SCALARS, &r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRoleServerSaveStateForUpgrade(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleServerSaveStateForUpgrade *r)
{
	ndr_print_struct(ndr, name, "dssetup_DsRoleServerSaveStateForUpgrade");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "dssetup_DsRoleServerSaveStateForUpgrade");
		ndr->depth++;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		ndr_print_struct(ndr, "out", "dssetup_DsRoleServerSaveStateForUpgrade");
		ndr->depth++;
		ndr_print_WERROR(ndr, "result", r->out.result);
		ndr->depth--;
	}
	ndr->depth--;
}

static enum ndr_err_code ndr_push_dssetup_DsRoleUpgradeDownlevelServer(struct ndr_push *ndr, int flags, const struct dssetup_DsRoleUpgradeDownlevelServer *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_push_WERROR(ndr, NDR_SCALARS, r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRoleUpgradeDownlevelServer(struct ndr_pull *ndr, int flags, struct dssetup_DsRoleUpgradeDownlevelServer *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_pull_WERROR(ndr, NDR_SCALARS, &r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRoleUpgradeDownlevelServer(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleUpgradeDownlevelServer *r)
{
	ndr_print_struct(ndr, name, "dssetup_DsRoleUpgradeDownlevelServer");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "dssetup_DsRoleUpgradeDownlevelServer");
		ndr->depth++;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		ndr_print_struct(ndr, "out", "dssetup_DsRoleUpgradeDownlevelServer");
		ndr->depth++;
		ndr_print_WERROR(ndr, "result", r->out.result);
		ndr->depth--;
	}
	ndr->depth--;
}

static enum ndr_err_code ndr_push_dssetup_DsRoleAbortDownlevelServerUpgrade(struct ndr_push *ndr, int flags, const struct dssetup_DsRoleAbortDownlevelServerUpgrade *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_push_WERROR(ndr, NDR_SCALARS, r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_dssetup_DsRoleAbortDownlevelServerUpgrade(struct ndr_pull *ndr, int flags, struct dssetup_DsRoleAbortDownlevelServerUpgrade *r)
{
	if (flags & NDR_IN) {
	}
	if (flags & NDR_OUT) {
		NDR_CHECK(ndr_pull_WERROR(ndr, NDR_SCALARS, &r->out.result));
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_dssetup_DsRoleAbortDownlevelServerUpgrade(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleAbortDownlevelServerUpgrade *r)
{
	ndr_print_struct(ndr, name, "dssetup_DsRoleAbortDownlevelServerUpgrade");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "dssetup_DsRoleAbortDownlevelServerUpgrade");
		ndr->depth++;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		ndr_print_struct(ndr, "out", "dssetup_DsRoleAbortDownlevelServerUpgrade");
		ndr->depth++;
		ndr_print_WERROR(ndr, "result", r->out.result);
		ndr->depth--;
	}
	ndr->depth--;
}

static const struct ndr_interface_call dssetup_calls[] = {
	{
		"dssetup_DsRoleGetPrimaryDomainInformation",
		sizeof(struct dssetup_DsRoleGetPrimaryDomainInformation),
		(ndr_push_flags_fn_t) ndr_push_dssetup_DsRoleGetPrimaryDomainInformation,
		(ndr_pull_flags_fn_t) ndr_pull_dssetup_DsRoleGetPrimaryDomainInformation,
		(ndr_print_function_t) ndr_print_disabled,
		{ 0, NULL },
		{ 0, NULL },
	},
	{
		"dssetup_DsRoleDnsNameToFlatName",
		sizeof(struct dssetup_DsRoleDnsNameToFlatName),
		(ndr_push_flags_fn_t) ndr_push_dssetup_DsRoleDnsNameToFlatName,
		(ndr_pull_flags_fn_t) ndr_pull_dssetup_DsRoleDnsNameToFlatName,
		(ndr_print_function_t) ndr_print_disabled,
		{ 0, NULL },
		{ 0, NULL },
	},
	{
		"dssetup_DsRoleDcAsDc",
		sizeof(struct dssetup_DsRoleDcAsDc),
		(ndr_push_flags_fn_t) ndr_push_dssetup_DsRoleDcAsDc,
		(ndr_pull_flags_fn_t) ndr_pull_dssetup_DsRoleDcAsDc,
		(ndr_print_function_t) ndr_print_disabled,
		{ 0, NULL },
		{ 0, NULL },
	},
	{
		"dssetup_DsRoleDcAsReplica",
		sizeof(struct dssetup_DsRoleDcAsReplica),
		(ndr_push_flags_fn_t) ndr_push_dssetup_DsRoleDcAsReplica,
		(ndr_pull_flags_fn_t) ndr_pull_dssetup_DsRoleDcAsReplica,
		(ndr_print_function_t) ndr_print_disabled,
		{ 0, NULL },
		{ 0, NULL },
	},
	{
		"dssetup_DsRoleDemoteDc",
		sizeof(struct dssetup_DsRoleDemoteDc),
		(ndr_push_flags_fn_t) ndr_push_dssetup_DsRoleDemoteDc,
		(ndr_pull_flags_fn_t) ndr_pull_dssetup_DsRoleDemoteDc,
		(ndr_print_function_t) ndr_print_disabled,
		{ 0, NULL },
		{ 0, NULL },
	},
	{
		"dssetup_DsRoleGetDcOperationProgress",
		sizeof(struct dssetup_DsRoleGetDcOperationProgress),
		(ndr_push_flags_fn_t) ndr_push_dssetup_DsRoleGetDcOperationProgress,
		(ndr_pull_flags_fn_t) ndr_pull_dssetup_DsRoleGetDcOperationProgress,
		(ndr_print_function_t) ndr_print_disabled,
		{ 0, NULL },
		{ 0, NULL },
	},
	{
		"dssetup_DsRoleGetDcOperationResults",
		sizeof(struct dssetup_DsRoleGetDcOperationResults),
		(ndr_push_flags_fn_t) ndr_push_dssetup_DsRoleGetDcOperationResults,
		(ndr_pull_flags_fn_t) ndr_pull_dssetup_DsRoleGetDcOperationResults,
		(ndr_print_function_t) ndr_print_disabled,
		{ 0, NULL },
		{ 0, NULL },
	},
	{
		"dssetup_DsRoleCancel",
		sizeof(struct dssetup_DsRoleCancel),
		(ndr_push_flags_fn_t) ndr_push_dssetup_DsRoleCancel,
		(ndr_pull_flags_fn_t) ndr_pull_dssetup_DsRoleCancel,
		(ndr_print_function_t) ndr_print_disabled,
		{ 0, NULL },
		{ 0, NULL },
	},
	{
		"dssetup_DsRoleServerSaveStateForUpgrade",
		sizeof(struct dssetup_DsRoleServerSaveStateForUpgrade),
		(ndr_push_flags_fn_t) ndr_push_dssetup_DsRoleServerSaveStateForUpgrade,
		(ndr_pull_flags_fn_t) ndr_pull_dssetup_DsRoleServerSaveStateForUpgrade,
		(ndr_print_function_t) ndr_print_disabled,
		{ 0, NULL },
		{ 0, NULL },
	},
	{
		"dssetup_DsRoleUpgradeDownlevelServer",
		sizeof(struct dssetup_DsRoleUpgradeDownlevelServer),
		(ndr_push_flags_fn_t) ndr_push_dssetup_DsRoleUpgradeDownlevelServer,
		(ndr_pull_flags_fn_t) ndr_pull_dssetup_DsRoleUpgradeDownlevelServer,
		(ndr_print_function_t) ndr_print_disabled,
		{ 0, NULL },
		{ 0, NULL },
	},
	{
		"dssetup_DsRoleAbortDownlevelServerUpgrade",
		sizeof(struct dssetup_DsRoleAbortDownlevelServerUpgrade),
		(ndr_push_flags_fn_t) ndr_push_dssetup_DsRoleAbortDownlevelServerUpgrade,
		(ndr_pull_flags_fn_t) ndr_pull_dssetup_DsRoleAbortDownlevelServerUpgrade,
		(ndr_print_function_t) ndr_print_disabled,
		{ 0, NULL },
		{ 0, NULL },
	},
	{ NULL, 0, NULL, NULL, NULL }
};

static const char * const dssetup_endpoint_strings[] = {
	"ncacn_np:[\\pipe\\lsarpc]", 
	"ncacn_np:[\\pipe\\lsass]", 
	"ncacn_ip_tcp:", 
	"ncalrpc:", 
};

static const struct ndr_interface_string_array dssetup_endpoints = {
	.count	= 4,
	.names	= dssetup_endpoint_strings
};

static const char * const dssetup_authservice_strings[] = {
	"host", 
};

static const struct ndr_interface_string_array dssetup_authservices = {
	.count	= 1,
	.names	= dssetup_authservice_strings
};


const struct ndr_interface_table ndr_table_dssetup = {
	.name		= "dssetup",
	.syntax_id	= {
		{0x3919286a,0xb10c,0x11d0,{0x9b,0xa8},{0x00,0xc0,0x4f,0xd9,0x2e,0xf5}},
		NDR_DSSETUP_VERSION
	},
	.helpstring	= NDR_DSSETUP_HELPSTRING,
	.num_calls	= 11,
	.calls		= dssetup_calls,
	.endpoints	= &dssetup_endpoints,
	.authservices	= &dssetup_authservices
};

