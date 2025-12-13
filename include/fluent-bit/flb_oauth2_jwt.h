/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_OAUTH2_JWT_H
#define FLB_OAUTH2_JWT_H

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_config_map.h>

struct flb_oauth2_jwt_cfg {
    int         validate;                 /* enable validation */
    flb_sds_t   issuer;                   /* expected issuer */
    flb_sds_t   jwks_url;                 /* JWKS endpoint */
    flb_sds_t   allowed_audience;         /* audience claim to enforce */
    struct mk_list *allowed_clients;      /* list of authorized azp/client_id */
    int         jwks_refresh_interval;    /* refresh cadence in seconds */
};

struct flb_oauth2_jwt_ctx;

/* Allocate and populate a validation context from configuration. */
struct flb_oauth2_jwt_ctx *flb_oauth2_jwt_context_create(struct flb_oauth2_jwt_cfg *cfg);

/* Release validation resources. */
void flb_oauth2_jwt_context_destroy(struct flb_oauth2_jwt_ctx *ctx);

/* Validate a bearer token (JWT) using the supplied context. */
int flb_oauth2_jwt_validate(struct flb_oauth2_jwt_ctx *ctx,
                            const char *authorization_header,
                            size_t authorization_header_len);

#endif
