/* header auto-generated by pidl */

#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/unixinfo.h"

#ifndef _HEADER_NDR_unixinfo
#define _HEADER_NDR_unixinfo

#define NDR_UNIXINFO_UUID "9c54e310-a955-4885-bd31-78787147dfa6"
#define NDR_UNIXINFO_VERSION 0.0
#define NDR_UNIXINFO_NAME "unixinfo"
#define NDR_UNIXINFO_HELPSTRING "Unixinfo specific stuff"
extern const struct ndr_interface_table ndr_table_unixinfo;
#define NDR_UNIXINFO_SIDTOUID (0x00)

#define NDR_UNIXINFO_UIDTOSID (0x01)

#define NDR_UNIXINFO_SIDTOGID (0x02)

#define NDR_UNIXINFO_GIDTOSID (0x03)

#define NDR_UNIXINFO_GETPWUID (0x04)

#define NDR_UNIXINFO_CALL_COUNT (5)
void ndr_print_unixinfo_GetPWUidInfo(struct ndr_print *ndr, const char *name, const struct unixinfo_GetPWUidInfo *r);
void ndr_print_unixinfo_SidToUid(struct ndr_print *ndr, const char *name, int flags, const struct unixinfo_SidToUid *r);
void ndr_print_unixinfo_UidToSid(struct ndr_print *ndr, const char *name, int flags, const struct unixinfo_UidToSid *r);
void ndr_print_unixinfo_SidToGid(struct ndr_print *ndr, const char *name, int flags, const struct unixinfo_SidToGid *r);
void ndr_print_unixinfo_GidToSid(struct ndr_print *ndr, const char *name, int flags, const struct unixinfo_GidToSid *r);
void ndr_print_unixinfo_GetPWUid(struct ndr_print *ndr, const char *name, int flags, const struct unixinfo_GetPWUid *r);
#endif /* _HEADER_NDR_unixinfo */
