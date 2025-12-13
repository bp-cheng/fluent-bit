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
#include <fluent-bit/flb_base64.h>

#include <ctype.h>
#include <string.h>
#include <strings.h>

#include <jsmn/jsmn.h>


struct flb_oauth2_jwt_ctx {
    struct flb_oauth2_jwt_cfg cfg;
};

const char *flb_oauth2_jwt_status_message(int status)
{
    switch (status) {
    case FLB_OAUTH2_JWT_OK:
        return "ok";
    case FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case FLB_OAUTH2_JWT_ERR_SEGMENT_COUNT:
        return "jwt must contain 3 segments";
    case FLB_OAUTH2_JWT_ERR_BASE64_HEADER:
        return "unable to decode header";
    case FLB_OAUTH2_JWT_ERR_BASE64_PAYLOAD:
        return "unable to decode payload";
    case FLB_OAUTH2_JWT_ERR_BASE64_SIGNATURE:
        return "unable to decode signature";
    case FLB_OAUTH2_JWT_ERR_JSON_HEADER:
        return "invalid header json";
    case FLB_OAUTH2_JWT_ERR_JSON_PAYLOAD:
        return "invalid payload json";
    case FLB_OAUTH2_JWT_ERR_MISSING_KID:
        return "missing kid in header";
    case FLB_OAUTH2_JWT_ERR_ALG_UNSUPPORTED:
        return "unsupported alg";
    case FLB_OAUTH2_JWT_ERR_MISSING_EXP:
        return "missing exp claim";
    case FLB_OAUTH2_JWT_ERR_MISSING_ISS:
        return "missing iss claim";
    case FLB_OAUTH2_JWT_ERR_MISSING_AUD:
        return "missing aud claim";
    case FLB_OAUTH2_JWT_ERR_MISSING_BEARER_TOKEN:
        return "missing bearer token";
    case FLB_OAUTH2_JWT_ERR_MISSING_AUTH_HEADER:
        return "missing authorization header";
    case FLB_OAUTH2_JWT_ERR_VALIDATION_UNAVAILABLE:
        return "validation not implemented";
    default:
        return "unknown error";
    }
}

static void oauth2_jwt_destroy_claims(struct flb_oauth2_jwt_claims *claims)
{
    if (!claims) {
        return;
    }

    if (claims->kid) {
        flb_sds_destroy(claims->kid);
    }

    if (claims->alg) {
        flb_sds_destroy(claims->alg);
    }

    if (claims->issuer) {
        flb_sds_destroy(claims->issuer);
    }

    if (claims->audience) {
        flb_sds_destroy(claims->audience);
    }

    if (claims->client_id) {
        flb_sds_destroy(claims->client_id);
    }
}

void flb_oauth2_jwt_destroy(struct flb_oauth2_jwt *jwt)
{
    if (!jwt) {
        return;
    }

    oauth2_jwt_destroy_claims(&jwt->claims);

    if (jwt->header_json) {
        flb_sds_destroy(jwt->header_json);
    }

    if (jwt->payload_json) {
        flb_sds_destroy(jwt->payload_json);
    }

    if (jwt->signing_input) {
        flb_sds_destroy(jwt->signing_input);
    }

    if (jwt->signature) {
        flb_free(jwt->signature);
    }
}

static int oauth2_jwt_token_strcmp(const char *json, jsmntok_t *tok, const char *cmp)
{
    int len = (tok->end - tok->start);

    if (len != (int) strlen(cmp)) {
        return -1;
    }

    return strncmp(json + tok->start, cmp, len);
}

static int oauth2_jwt_parse_json_tokens(const char *json,
                                        size_t json_len,
                                        jsmntok_t **tokens_out,
                                        int *tokens_size_out,
                                        int invalid_error)
{
    int ret;
    jsmn_parser parser;
    int tokens_size = 32;
    jsmntok_t *tokens = NULL;

    jsmn_init(&parser);

    while (1) {
        flb_free(tokens);
        tokens = flb_calloc(1, sizeof(jsmntok_t) * tokens_size);
        if (!tokens) {
            flb_errno();
            return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
        }

        ret = jsmn_parse(&parser, json, json_len, tokens, tokens_size);
        if (ret != JSMN_ERROR_NOMEM) {
            break;
        }

        tokens_size *= 2;
    }

    if (ret < 1 || tokens[0].type != JSMN_OBJECT) {
        flb_free(tokens);
        return invalid_error;
    }

    *tokens_out = tokens;
    *tokens_size_out = ret;
    return FLB_OAUTH2_JWT_OK;
}

static int oauth2_jwt_base64url_decode(const char *segment,
                                       size_t segment_len,
                                       unsigned char **decoded,
                                       size_t *decoded_len,
                                       int base64_error_code)
{
    int ret;
    size_t i;
    size_t padding = 0;
    size_t padded_len;
    char *padded;

    if (!segment || !decoded || !decoded_len) {
        return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
    }

    padding = (4 - (segment_len % 4)) % 4;
    padded_len = segment_len + padding;

    padded = flb_malloc(padded_len + 1);
    if (!padded) {
        flb_errno();
        return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
    }

    for (i = 0; i < segment_len; i++) {
        if (segment[i] == '-') {
            padded[i] = '+';
        }
        else if (segment[i] == '_') {
            padded[i] = '/';
        }
        else {
            padded[i] = segment[i];
        }
    }

    for (i = 0; i < padding; i++) {
        padded[segment_len + i] = '=';
    }
    padded[padded_len] = '\0';

    ret = flb_base64_decode(NULL, 0, decoded_len,
                            (unsigned char *) padded, padded_len);
    if (ret != 0) {
        flb_free(padded);
        return base64_error_code;
    }

    *decoded = flb_malloc(*decoded_len + 1);
    if (!*decoded) {
        flb_errno();
        flb_free(padded);
        return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
    }

    ret = flb_base64_decode(*decoded, *decoded_len, decoded_len,
                            (unsigned char *) padded, padded_len);
    flb_free(padded);

    if (ret != 0) {
        flb_free(*decoded);
        *decoded = NULL;
        return base64_error_code;
    }

    (*decoded)[*decoded_len] = '\0';
    return FLB_OAUTH2_JWT_OK;
}

static flb_sds_t oauth2_jwt_token_to_sds(const char *json, jsmntok_t *tok)
{
    return flb_sds_create_len(json + tok->start, tok->end - tok->start);
}

static int oauth2_jwt_parse_header(const char *json, size_t json_len,
                                   struct flb_oauth2_jwt_claims *claims)
{
    int i;
    int tokens_size;
    int ret;
    jsmntok_t *tokens = NULL;

    ret = oauth2_jwt_parse_json_tokens(json, json_len, &tokens, &tokens_size,
                                       FLB_OAUTH2_JWT_ERR_JSON_HEADER);
    if (ret != FLB_OAUTH2_JWT_OK) {
        return ret;
    }

    for (i = 1; i < tokens_size; i++) {
        jsmntok_t *key = &tokens[i];
        jsmntok_t *val;

        if (key->type != JSMN_STRING) {
            continue;
        }

        i++;
        if (i >= tokens_size) {
            break;
        }

        val = &tokens[i];

        if (oauth2_jwt_token_strcmp(json, key, "kid") == 0) {
            claims->kid = oauth2_jwt_token_to_sds(json, val);
        }
        else if (oauth2_jwt_token_strcmp(json, key, "alg") == 0) {
            claims->alg = oauth2_jwt_token_to_sds(json, val);
        }
    }

    flb_free(tokens);

    if (!claims->kid) {
        return FLB_OAUTH2_JWT_ERR_MISSING_KID;
    }

    if (!claims->alg || strcmp(claims->alg, "RS256") != 0) {
        return FLB_OAUTH2_JWT_ERR_ALG_UNSUPPORTED;
    }

    return FLB_OAUTH2_JWT_OK;
}

static int oauth2_jwt_parse_payload(const char *json, size_t json_len,
                                    struct flb_oauth2_jwt_claims *claims)
{
    int i;
    int tokens_size;
    int ret;
    jsmntok_t *tokens = NULL;

    ret = oauth2_jwt_parse_json_tokens(json, json_len, &tokens, &tokens_size,
                                       FLB_OAUTH2_JWT_ERR_JSON_PAYLOAD);
    if (ret != FLB_OAUTH2_JWT_OK) {
        return ret;
    }

    for (i = 1; i < tokens_size; i++) {
        jsmntok_t *key = &tokens[i];
        jsmntok_t *val;

        if (key->type != JSMN_STRING) {
            continue;
        }

        i++;
        if (i >= tokens_size) {
            break;
        }

        val = &tokens[i];

        if (oauth2_jwt_token_strcmp(json, key, "exp") == 0) {
            flb_sds_t tmp;

            tmp = oauth2_jwt_token_to_sds(json, val);
            if (tmp) {
                claims->expiration = strtoull(tmp, NULL, 10);
                flb_sds_destroy(tmp);
            }
        }
        else if (oauth2_jwt_token_strcmp(json, key, "iss") == 0) {
            claims->issuer = oauth2_jwt_token_to_sds(json, val);
        }
        else if (oauth2_jwt_token_strcmp(json, key, "aud") == 0) {
            if (val->type == JSMN_ARRAY && val->size > 0) {
                claims->audience = oauth2_jwt_token_to_sds(json, val + 1);
                i += val->size;
            }
            else {
                claims->audience = oauth2_jwt_token_to_sds(json, val);
            }
        }
        else if (oauth2_jwt_token_strcmp(json, key, "azp") == 0 ||
                 oauth2_jwt_token_strcmp(json, key, "client_id") == 0) {
            claims->client_id = oauth2_jwt_token_to_sds(json, val);
        }
    }

    flb_free(tokens);

    if (claims->expiration == 0) {
        return FLB_OAUTH2_JWT_ERR_MISSING_EXP;
    }

    if (!claims->issuer) {
        return FLB_OAUTH2_JWT_ERR_MISSING_ISS;
    }

    if (!claims->audience) {
        return FLB_OAUTH2_JWT_ERR_MISSING_AUD;
    }

    return FLB_OAUTH2_JWT_OK;
}

int flb_oauth2_jwt_parse(const char *token, size_t token_len,
                         struct flb_oauth2_jwt *jwt)
{
    int ret;
    int segment = 0;
    size_t i;
    size_t start = 0;
    const char *parts[3] = {0};
    size_t parts_len[3] = {0};
    unsigned char *decoded = NULL;
    size_t decoded_len = 0;

    if (!token || token_len == 0 || !jwt) {
        return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
    }

    memset(jwt, 0, sizeof(struct flb_oauth2_jwt));

    for (i = 0; i <= token_len; i++) {
        if (i == token_len || token[i] == '.') {
            if (segment >= 3) {
                return FLB_OAUTH2_JWT_ERR_SEGMENT_COUNT;
            }

            parts[segment] = token + start;
            parts_len[segment] = i - start;
            segment++;
            start = i + 1;
        }
    }

    if (segment != 3) {
        return FLB_OAUTH2_JWT_ERR_SEGMENT_COUNT;
    }

    jwt->signing_input = flb_sds_create_len(token, parts_len[0] + parts_len[1] + 1);
    if (!jwt->signing_input) {
        return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
    }

    jwt->signing_input[parts_len[0]] = '.';
    memcpy(jwt->signing_input, parts[0], parts_len[0]);
    memcpy(jwt->signing_input + parts_len[0] + 1, parts[1], parts_len[1]);
    jwt->signing_input[parts_len[0] + parts_len[1] + 1] = '\0';

    ret = oauth2_jwt_base64url_decode(parts[0], parts_len[0], &decoded, &decoded_len,
                                      FLB_OAUTH2_JWT_ERR_BASE64_HEADER);
    if (ret != FLB_OAUTH2_JWT_OK) {
        flb_oauth2_jwt_destroy(jwt);
        return ret;
    }

    jwt->header_json = flb_sds_create_len((const char *) decoded, decoded_len);
    flb_free(decoded);
    decoded = NULL;
    decoded_len = 0;
    if (!jwt->header_json) {
        flb_oauth2_jwt_destroy(jwt);
        return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
    }

    ret = oauth2_jwt_parse_header(jwt->header_json, flb_sds_len(jwt->header_json),
                                  &jwt->claims);
    if (ret != FLB_OAUTH2_JWT_OK) {
        flb_oauth2_jwt_destroy(jwt);
        return ret;
    }

    ret = oauth2_jwt_base64url_decode(parts[1], parts_len[1], &decoded, &decoded_len,
                                      FLB_OAUTH2_JWT_ERR_BASE64_PAYLOAD);
    if (ret != FLB_OAUTH2_JWT_OK) {
        flb_oauth2_jwt_destroy(jwt);
        return ret;
    }

    jwt->payload_json = flb_sds_create_len((const char *) decoded, decoded_len);
    flb_free(decoded);
    decoded = NULL;
    decoded_len = 0;
    if (!jwt->payload_json) {
        flb_oauth2_jwt_destroy(jwt);
        return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
    }

    ret = oauth2_jwt_parse_payload(jwt->payload_json,
                                   flb_sds_len(jwt->payload_json),
                                   &jwt->claims);
    if (ret != FLB_OAUTH2_JWT_OK) {
        flb_oauth2_jwt_destroy(jwt);
        return ret;
    }

    ret = oauth2_jwt_base64url_decode(parts[2], parts_len[2], &decoded, &decoded_len,
                                      FLB_OAUTH2_JWT_ERR_BASE64_SIGNATURE);
    if (ret != FLB_OAUTH2_JWT_OK) {
        flb_oauth2_jwt_destroy(jwt);
        return ret;
    }

    jwt->signature = decoded;
    jwt->signature_len = decoded_len;

    return FLB_OAUTH2_JWT_OK;
}

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
    int status;
    size_t token_start = 0;
    size_t token_len;
    struct flb_oauth2_jwt jwt;

    if (!ctx) {
        return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
    }

    if (!ctx->cfg.validate) {
        return FLB_OAUTH2_JWT_OK;
    }

    if (!authorization_header || authorization_header_len == 0) {
        return FLB_OAUTH2_JWT_ERR_MISSING_AUTH_HEADER;
    }

    while (token_start < authorization_header_len &&
           isspace((unsigned char) authorization_header[token_start])) {
        token_start++;
    }

    if (authorization_header_len - token_start < sizeof("Bearer ") - 1 ||
        strncasecmp(&authorization_header[token_start], "Bearer ", sizeof("Bearer ") - 1) != 0) {
        return FLB_OAUTH2_JWT_ERR_MISSING_BEARER_TOKEN;
    }

    token_start += sizeof("Bearer ") - 1;
    token_len = authorization_header_len - token_start;

    while (token_len > 0 &&
           isspace((unsigned char) authorization_header[token_start + token_len - 1])) {
        token_len--;
    }

    status = flb_oauth2_jwt_parse(&authorization_header[token_start], token_len, &jwt);
    if (status != FLB_OAUTH2_JWT_OK) {
        flb_warn("[oauth2_jwt] failed to parse token: %s",
                 flb_oauth2_jwt_status_message(status));
        return status;
    }

    flb_warn("OAuth2 JWT validation requested but not fully implemented yet; rejecting request after parsing");
    flb_oauth2_jwt_destroy(&jwt);

    return FLB_OAUTH2_JWT_ERR_VALIDATION_UNAVAILABLE;
}

