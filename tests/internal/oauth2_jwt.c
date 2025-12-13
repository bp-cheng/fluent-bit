#include <fluent-bit/flb_oauth2_jwt.h>

#include "flb_tests_internal.h"
#include <string.h>

static const char *VALID_JWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0.eyJleHAiOjE3MTAwMDAwMDAsImlzcyI6Imlzc3VlciIsImF1ZCI6ImF1ZGllbmNlIiwiYXpwIjoiY2xpZW50LTEifQ.c2ln";
static const char *INVALID_SEGMENTS = "abc.def";
static const char *BAD_BASE64 = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0#.eyJleHAiOjE3MTAwMDAwMDAsImlzcyI6Imlzc3VlciIsImF1ZCI6ImF1ZGllbmNlIiwiYXpwIjoiY2xpZW50LTEifQ.c2ln";
static const char *MISSING_KID = "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE3MTAwMDAwMDAsImlzcyI6Imlzc3VlciIsImF1ZCI6ImF1ZGllbmNlIiwiYXpwIjoiY2xpZW50LTEifQ.c2ln";
static const char *BAD_ALG = "eyJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Qta2V5In0.eyJleHAiOjE3MTAwMDAwMDAsImlzcyI6Imlzc3VlciIsImF1ZCI6ImF1ZGllbmNlIiwiYXpwIjoiY2xpZW50LTEifQ.c2ln";

static void test_valid_jwt_parses()
{
    int ret;
    struct flb_oauth2_jwt jwt;

    ret = flb_oauth2_jwt_parse(VALID_JWT, strlen(VALID_JWT), &jwt);
    TEST_CHECK(ret == FLB_OAUTH2_JWT_OK);
    TEST_CHECK(jwt.signature != NULL && jwt.signature_len > 0);
    TEST_CHECK(jwt.claims.expiration == 1710000000);
    TEST_CHECK(strcmp(jwt.claims.kid, "test-key") == 0);
    TEST_CHECK(strcmp(jwt.claims.alg, "RS256") == 0);
    TEST_CHECK(strcmp(jwt.claims.issuer, "issuer") == 0);
    TEST_CHECK(strcmp(jwt.claims.audience, "audience") == 0);
    TEST_CHECK(strcmp(jwt.claims.client_id, "client-1") == 0);
    TEST_CHECK(jwt.signing_input != NULL);

    flb_oauth2_jwt_destroy(&jwt);
}

static void test_invalid_segments()
{
    int ret;
    struct flb_oauth2_jwt jwt;

    ret = flb_oauth2_jwt_parse(INVALID_SEGMENTS, strlen(INVALID_SEGMENTS), &jwt);
    TEST_CHECK(ret == FLB_OAUTH2_JWT_ERR_SEGMENT_COUNT);
}

static void test_bad_base64()
{
    int ret;
    struct flb_oauth2_jwt jwt;

    ret = flb_oauth2_jwt_parse(BAD_BASE64, strlen(BAD_BASE64), &jwt);
    TEST_CHECK(ret == FLB_OAUTH2_JWT_ERR_BASE64_HEADER);
}

static void test_missing_kid()
{
    int ret;
    struct flb_oauth2_jwt jwt;

    ret = flb_oauth2_jwt_parse(MISSING_KID, strlen(MISSING_KID), &jwt);
    TEST_CHECK(ret == FLB_OAUTH2_JWT_ERR_MISSING_KID);
}

static void test_bad_alg()
{
    int ret;
    struct flb_oauth2_jwt jwt;

    ret = flb_oauth2_jwt_parse(BAD_ALG, strlen(BAD_ALG), &jwt);
    TEST_CHECK(ret == FLB_OAUTH2_JWT_ERR_ALG_UNSUPPORTED);
}

TEST_LIST = {
    {"valid_jwt_parses", test_valid_jwt_parses},
    {"invalid_segments", test_invalid_segments},
    {"bad_base64", test_bad_base64},
    {"missing_kid", test_missing_kid},
    {"bad_alg", test_bad_alg},
    {0}
};
