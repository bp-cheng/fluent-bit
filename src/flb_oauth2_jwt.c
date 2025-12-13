/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_oauth2_jwt.h>

#include <string.h>


struct flb_oauth2_jwt_ctx {
    struct flb_oauth2_jwt_cfg cfg;
};

static void oauth2_jwt_free_cfg(struct flb_oauth2_jwt_cfg *cfg)
{
    if (!cfg) {
        return;
    }

    if (cfg->issuer) {
        flb_sds_destroy(cfg->issuer);
    }

    if (cfg->jwks_url) {
        flb_sds_destroy(cfg->jwks_url);
    }

    if (cfg->allowed_audience) {
        flb_sds_destroy(cfg->allowed_audience);
    }
}

struct flb_oauth2_jwt_ctx *flb_oauth2_jwt_context_create(struct flb_oauth2_jwt_cfg *cfg)
{
    struct flb_oauth2_jwt_ctx *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_oauth2_jwt_ctx));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    if (cfg != NULL) {
        memcpy(&ctx->cfg, cfg, sizeof(struct flb_oauth2_jwt_cfg));
    }

    return ctx;
}

void flb_oauth2_jwt_context_destroy(struct flb_oauth2_jwt_ctx *ctx)
{
    if (!ctx) {
        return;
    }

    oauth2_jwt_free_cfg(&ctx->cfg);
    flb_free(ctx);
}

int flb_oauth2_jwt_validate(struct flb_oauth2_jwt_ctx *ctx,
                            const char *authorization_header,
                            size_t authorization_header_len)
{
    (void) authorization_header;
    (void) authorization_header_len;

    if (!ctx) {
        return -1;
    }

    if (!ctx->cfg.validate) {
        return 0;
    }

    flb_warn("OAuth2 JWT validation requested but not fully implemented yet; rejecting request");
    return -1;
}

