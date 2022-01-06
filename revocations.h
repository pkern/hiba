/*
 * Copyright 2021 The HIBA Authors
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */
#ifndef _REVOCATIONS_H
#define _REVOCATIONS_H

#include <sys/types.h>

#include "sshbuf.h"

/*
 * HIBA GRL magic header
 */
#define HIBA_GRL_MAGIC 0x4847524c

struct hibagrl;

/* Allocate a hibagrl object.
 * Result must be freed using the SSH API hibagrl_free. */
struct hibagrl *hibagrl_new();

/* Initializes an HIBA GRL object.
 * This hibagrl object is mapped and ready to accept new revocations. */
void hibagrl_init(struct hibagrl *grl, const char *comment);

/* Load an existing serialzied grant revocation list.
 * This hibagrl is flat and ready to accept checks.
 * The sshbuf must not be modified or freed while the hibagrl object is used. */
int hibagrl_decode(struct hibagrl *grl, struct sshbuf *blob);

/* Releases resources allocated by a hibagrl object.
 * This function supports both flat and mapped objects. */
void hibagrl_free();

/* Take a flat hibagrl object and map it for editing. */
int hibagrl_map(struct hibagrl *grl);

/* Serializes a flat grant revocation list.*/
int hibagrl_encode(const struct hibagrl *grl, struct sshbuf *blob);

/* Revoke a range of grants from a certificate.
 * Only mapped hibagrl object can be edited.
 * The grants to be revoked are identified by a certificate serial, a grant ID
 * range (inclusive). A grant ID offsets are zero based. */
int hibagrl_revoke_grant(struct hibagrl *grl, u_int64_t serial, u_int32_t lo,
			 u_int32_t hi);

/* Verify whether a grant in a certificate is revoked.
 * Only flat hibagrl object can be used for revocation checks. */
int hibagrl_check(const struct hibagrl *grl, u_int64_t serial, u_int32_t grant_id);

/* Getter for the GRL version.
 * On error, returns a negative error code. */
int hibagrl_version(const struct hibagrl *grl);

/* Getter for the GRL comment.
 * On error, returns the corresponding error string. */
const char* hibagrl_comment(const struct hibagrl *grl);

/* Getter for the GRL version.
 * On error, returns the 0 timestamp. */
u_int64_t hibagrl_timestamp(const struct hibagrl *grl);

/* Getter for the GRL version.
 * On error, returns the 0 serials count. */
u_int64_t hibagrl_serials_count(const struct hibagrl *grl);

#ifdef HIBA_INTERNAL
/* Dump the content of a GRL object into human readable format.
 * The serial parameter can be used to filter for one serial if not NULL. */
int hibagrl_dump_content(const struct hibagrl *grl, u_int64_t *serial, FILE *f);
#endif /* HIBA_INTERNAL */

#endif  // _REVOCATIONS_H
