#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include <util_mosq.h>

static void match_helper(const char *sub, const char *topic)
{
	int rc;
	bool match;

	rc = mosquitto_topic_matches_sub(sub, topic, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);
	if(match == false){
		printf("1: %s:%s\n", sub, topic);
	}

	rc = mosquitto_topic_matches_sub2(sub, strlen(sub), topic, strlen(topic), &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);
	if(match == false){
		printf("2: %s:%s\n", sub, topic);
	}
}

static void no_match_helper(int rc_expected, const char *sub, const char *topic)
{
	int rc;
	bool match;

	rc = mosquitto_topic_matches_sub(sub, topic, &match);
	CU_ASSERT_EQUAL(rc, rc_expected);
	if(rc != rc_expected){
		printf("%d:%d %s:%s\n", rc, rc_expected, sub, topic);
	}
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub2(sub, strlen(sub), topic, strlen(topic), &match);
	CU_ASSERT_EQUAL(rc, rc_expected);
	if(rc != rc_expected){
		printf("%d:%d %s:%s\n", rc, rc_expected, sub, topic);
	}
	CU_ASSERT_EQUAL(match, false);
}

/* ========================================================================
 * EMPTY INPUT
 * ======================================================================== */

static void TEST_empty_input(void)
{
	int rc;
	bool match;

	rc = mosquitto_topic_matches_sub("sub", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub(NULL, "topic", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub(NULL, NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub("sub", "", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub("", "topic", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub("", "", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub2("sub", 3, NULL, 0, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub2(NULL, 0, "topic", 5, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub2(NULL, 0, NULL, 0, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub2("sub", 3, "", 0, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub2("", 0, "topic", 5, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub2("", 0, "", 0, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);
}

static void TEST_topic_pattern_empty_input(void)
{
	int rc;
	bool match;

	rc = mosquitto_topic_matches_sub_with_pattern(NULL, NULL, NULL, NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("sub", NULL, NULL, NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern(NULL, "topic", NULL, NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern(NULL, NULL, "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern(NULL, NULL, NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("sub", "", "", "", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("", "topic", "", "", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("", "", "clientid", "", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("", "", "", "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("%c", "topic", NULL, NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("%u", "topic", NULL, NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("%c", "", "", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("%u", "", NULL, "", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("test/%c/test", "test//test", "", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("test/%u/test", "test//test", NULL, "", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);
}

static void TEST_acl_pattern_empty_input(void)
{
	int rc;
	bool match;

	rc = mosquitto_sub_matches_acl_with_pattern(NULL, NULL, NULL, NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("acl", NULL, NULL, NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern(NULL, "sub", NULL, NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern(NULL, NULL, "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern(NULL, NULL, NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("acl", "", "", "", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("", "sub", "", "", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("", "", "clientid", "", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("", "", "", "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("%c", "sub", NULL, NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("%u", "sub", NULL, NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("%c", "", "", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("%u", "", NULL, "", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("test/%c/test", "test//test", "", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("test/%u/test", "test//test", NULL, "", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);
}

static void TEST_sub_match_empty_input(void)
{
	int rc;
	bool match;

	rc = mosquitto_sub_matches_acl("sub", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl(NULL, "topic", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl(NULL, NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl("sub", "", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl("", "topic", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl("", "", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_INVAL);
	CU_ASSERT_EQUAL(match, false);
}

/* ========================================================================
 * VALID MATCHING AND NON-MATCHING
 * ======================================================================== */

static void TEST_valid_matching(void)
{
	match_helper("foo/#", "foo/");
	match_helper("foo/#", "foo");
	match_helper("foo//bar", "foo//bar");
	match_helper("foo//+", "foo//bar");
	match_helper("foo/+/+/baz", "foo///baz");
	match_helper("foo/bar/+", "foo/bar/");
	match_helper("foo/bar", "foo/bar");
	match_helper("foo/+", "foo/bar");
	match_helper("foo/+/baz", "foo/bar/baz");
	match_helper("A/B/+/#", "A/B/B/C");
	match_helper("foo/+/#", "foo/bar/baz");
	match_helper("foo/+/#", "foo/bar");
	match_helper("#", "foo/bar/baz");
	match_helper("#", "foo/bar/baz");
	match_helper("#", "/foo/bar");
	match_helper("/#", "/foo/bar");
}


static void TEST_invalid_but_matching(void)
{
	/* Matching here is "naive treatment of the wildcards would produce a
	 * match". They shouldn't really match, they should fail. */
	no_match_helper(MOSQ_ERR_INVAL, "+foo", "+foo");
	no_match_helper(MOSQ_ERR_INVAL, "fo+o", "fo+o");
	no_match_helper(MOSQ_ERR_INVAL, "foo+", "foo+");
	no_match_helper(MOSQ_ERR_INVAL, "+foo/bar", "+foo/bar");
	no_match_helper(MOSQ_ERR_INVAL, "foo+/bar", "foo+/bar");
	no_match_helper(MOSQ_ERR_INVAL, "foo/+bar", "foo/+bar");
	no_match_helper(MOSQ_ERR_INVAL, "foo/bar+", "foo/bar+");

	no_match_helper(MOSQ_ERR_INVAL, "+foo", "afoo");
	no_match_helper(MOSQ_ERR_INVAL, "fo+o", "foao");
	no_match_helper(MOSQ_ERR_INVAL, "foo+", "fooa");
	no_match_helper(MOSQ_ERR_INVAL, "+foo/bar", "afoo/bar");
	no_match_helper(MOSQ_ERR_INVAL, "foo+/bar", "fooa/bar");
	no_match_helper(MOSQ_ERR_INVAL, "foo/+bar", "foo/abar");
	no_match_helper(MOSQ_ERR_INVAL, "foo/bar+", "foo/bara");

	no_match_helper(MOSQ_ERR_INVAL, "#foo", "#foo");
	no_match_helper(MOSQ_ERR_INVAL, "fo#o", "fo#o");
	no_match_helper(MOSQ_ERR_INVAL, "foo#", "foo#");
	no_match_helper(MOSQ_ERR_INVAL, "#foo/bar", "#foo/bar");
	no_match_helper(MOSQ_ERR_INVAL, "foo#/bar", "foo#/bar");
	no_match_helper(MOSQ_ERR_INVAL, "foo/#bar", "foo/#bar");
	no_match_helper(MOSQ_ERR_INVAL, "foo/bar#", "foo/bar#");

	no_match_helper(MOSQ_ERR_INVAL, "foo+", "fooa");

	no_match_helper(MOSQ_ERR_INVAL, "foo/+", "foo/+");
	no_match_helper(MOSQ_ERR_INVAL, "foo/#", "foo/+");
	no_match_helper(MOSQ_ERR_INVAL, "foo/+", "foo/bar/+");
	no_match_helper(MOSQ_ERR_INVAL, "foo/#", "foo/bar/+");

	no_match_helper(MOSQ_ERR_INVAL, "foo/+", "foo/#");
	no_match_helper(MOSQ_ERR_INVAL, "foo/#", "foo/#");
	no_match_helper(MOSQ_ERR_INVAL, "foo/+", "foo/bar/#");
	no_match_helper(MOSQ_ERR_INVAL, "foo/#", "foo/bar/#");
}


static void TEST_valid_no_matching(void)
{
	no_match_helper(MOSQ_ERR_SUCCESS, "test/6/#", "test/3");

	no_match_helper(MOSQ_ERR_SUCCESS, "foo/bar", "foo");
	no_match_helper(MOSQ_ERR_SUCCESS, "foo/+", "foo/bar/baz");
	no_match_helper(MOSQ_ERR_SUCCESS, "foo/+/baz", "foo/bar/bar");

	no_match_helper(MOSQ_ERR_SUCCESS, "foo/+/#", "fo2/bar/baz");

	no_match_helper(MOSQ_ERR_SUCCESS, "/#", "foo/bar");

	no_match_helper(MOSQ_ERR_SUCCESS, "#", "$SYS/bar");
	no_match_helper(MOSQ_ERR_SUCCESS, "$BOB/bar", "$SYS/bar");
}


static void TEST_invalid(void)
{
	no_match_helper(MOSQ_ERR_INVAL, "foo#", "foo");
	no_match_helper(MOSQ_ERR_INVAL, "fo#o/", "foo");
	no_match_helper(MOSQ_ERR_INVAL, "foo#", "fooa");
	no_match_helper(MOSQ_ERR_INVAL, "foo+", "foo");
	no_match_helper(MOSQ_ERR_INVAL, "foo/#a", "foo");
	no_match_helper(MOSQ_ERR_INVAL, "#a", "foo");
	no_match_helper(MOSQ_ERR_INVAL, "foo/#abc", "foo");
	no_match_helper(MOSQ_ERR_INVAL, "#abc", "foo");
	no_match_helper(MOSQ_ERR_INVAL, "/#a", "foo/bar");
}

/* ========================================================================
 * TOPIC MATCHES SUB PATTERNS
 * ======================================================================== */

static void TEST_topic_pattern_clientid(void)
{
	int rc;
	bool match;

	/* Sole pattern */
	rc = mosquitto_topic_matches_sub_with_pattern("%c", "clientid", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("%c", "clientid", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern at beginning */
	rc = mosquitto_topic_matches_sub_with_pattern("%c/test", "clientid/test", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("%c/test", "clientid/test", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern at end */
	rc = mosquitto_topic_matches_sub_with_pattern("test/%c", "test/clientid", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("test/%c", "test/clientid", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern in middle */
	rc = mosquitto_topic_matches_sub_with_pattern("test/%c/test", "test/clientid/test", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("test/%c/test", "test/clientid/test", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Repeated pattern */
	rc = mosquitto_topic_matches_sub_with_pattern("test/%c/%c/test", "test/clientid/clientid/test", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("test/%c/%c/test", "test/clientid/clientid/test", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Not a pattern */
	rc = mosquitto_topic_matches_sub_with_pattern("test/%count", "test/clientid", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);
}

static void TEST_topic_pattern_username(void)
{
	int rc;
	bool match;

	/* Sole pattern */
	rc = mosquitto_topic_matches_sub_with_pattern("%u", "username", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("%u", "username", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern at beginning */
	rc = mosquitto_topic_matches_sub_with_pattern("%u/test", "username/test", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("%u/test", "username/test", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern at end */
	rc = mosquitto_topic_matches_sub_with_pattern("test/%u", "test/username", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("test/%u", "test/username", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern in middle */
	rc = mosquitto_topic_matches_sub_with_pattern("test/%u/test", "test/username/test", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("test/%u/test", "test/username/test", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Repeated pattern */
	rc = mosquitto_topic_matches_sub_with_pattern("test/%u/%u/test", "test/username/username/test", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("test/%u/%u/test", "test/username/username/test", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Not a pattern */
	rc = mosquitto_topic_matches_sub_with_pattern("test/%username", "test/username", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);
}

static void TEST_topic_pattern_both(void)
{
	int rc;
	bool match;

	/* Sole pattern */
	rc = mosquitto_topic_matches_sub_with_pattern("%u/%c", "username/clientid", "clientid", "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("%u/%c", "username/clientid", "clientid", "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("%u/%c", "username/clientid", "nomatch", "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("%u/%c", "username/clientid", "nomatch", "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern in middle */
	rc = mosquitto_topic_matches_sub_with_pattern("test/%c/%u/test", "test/clientid/username/test", "clientid", "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("test/%c/%u/test", "test/clientid/username/test", "clientid", "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("test/%c/%u/test", "test/clientid/username/test", "nomatch", "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("test/%c/%u/test", "test/clientid/username/test", "nomatch", "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Repeated pattern */
	rc = mosquitto_topic_matches_sub_with_pattern("test/%u/%c/%c/%u/test", "test/username/clientid/clientid/username/test", "clientid", "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	/* Not a pattern */
	rc = mosquitto_topic_matches_sub_with_pattern("test/%username/%client", "test/username/clientid", "clientid", "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Not a pattern */
	rc = mosquitto_topic_matches_sub_with_pattern("test/a%u/a%c", "test/ausername/aclientid", "clientid", "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);
}

static void TEST_topic_pattern_wildcard(void)
{
	int rc;
	bool match;

	/* Malicious */
	/* ========= */

	/* / in client id */
	rc = mosquitto_topic_matches_sub_with_pattern("%c", "clientid/test", "clientid/test", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* / in username */
	rc = mosquitto_topic_matches_sub_with_pattern("%u", "username/test", NULL, "username/test", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* + in client id */
	rc = mosquitto_topic_matches_sub_with_pattern("%c", "clientid", "+", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* + in username */
	rc = mosquitto_topic_matches_sub_with_pattern("username/%u/+", "username/test/+", NULL, "+", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Valid */
	/* ========= */

	/* Ends in + */
	rc = mosquitto_topic_matches_sub_with_pattern("clientid/%c/+", "clientid/test/topic", "test", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("clientid/%c/+", "clientid/test/topic", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("username/%u/+", "username/test/topic", NULL, "test", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("username/%u/+", "username/test/topic", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Ends in # */
	rc = mosquitto_topic_matches_sub_with_pattern("clientid/%c/#", "clientid/test/topic", "test", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("clientid/%c/#", "clientid/test/topic", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("username/%u/#", "username/test/topic", NULL, "test", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("username/%u/#", "username/test/topic", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("clientid/%c/#", "clientid/test", "test", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("clientid/%c/#", "clientid/test", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_topic_matches_sub_with_pattern("pattern/%u/#", "pattern/username", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_topic_matches_sub_with_pattern("username/%u/#", "username/test", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);
}

/* ========================================================================
 * SUB MATCHES ACL PATTERNS
 * ======================================================================== */

static void TEST_acl_pattern_clientid(void)
{
	int rc;
	bool match;

	/* Sole pattern */
	rc = mosquitto_sub_matches_acl_with_pattern("%c", "clientid", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("%c", "clientid", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern at beginning */
	rc = mosquitto_sub_matches_acl_with_pattern("%c/test", "clientid/test", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("%c/test", "clientid/test", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern at end */
	rc = mosquitto_sub_matches_acl_with_pattern("test/%c", "test/clientid", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("test/%c", "test/clientid", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern in middle */
	rc = mosquitto_sub_matches_acl_with_pattern("test/%c/test", "test/clientid/test", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("test/%c/test", "test/clientid/test", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Repeated pattern */
	rc = mosquitto_sub_matches_acl_with_pattern("test/%c/%c/test", "test/clientid/clientid/test", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("test/%c/%c/test", "test/clientid/clientid/test", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Not a pattern */
	rc = mosquitto_sub_matches_acl_with_pattern("test/%count", "test/clientid", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Now repeated, with wildcards: */

	/* Pattern at beginning */
	rc = mosquitto_sub_matches_acl_with_pattern("%c/test/+", "clientid/test/+", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("%c/test/+", "clientid/test/+", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("%c/test/#", "clientid/test/+", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("%c/test/#", "clientid/test/+", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern at end */
	rc = mosquitto_sub_matches_acl_with_pattern("+/test/%c", "+/test/clientid", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("+/test/%c", "+/test/clientid", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern in middle */
	rc = mosquitto_sub_matches_acl_with_pattern("test/%c/+/test", "test/clientid/+/test", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("test/%c/+/test", "test/clientid/+/test", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Repeated pattern */
	rc = mosquitto_sub_matches_acl_with_pattern("test/%c/%c/test/+", "test/clientid/clientid/test/test", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("test/%c/%c/test/+", "test/clientid/clientid/test/test", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Not a pattern */
	rc = mosquitto_sub_matches_acl_with_pattern("+/test/%count", "+/test/clientid", "clientid", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);
}

static void TEST_acl_pattern_username(void)
{
	int rc;
	bool match;

	/* Sole pattern */
	rc = mosquitto_sub_matches_acl_with_pattern("%u", "username", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("%u", "username", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern at beginning */
	rc = mosquitto_sub_matches_acl_with_pattern("%u/test", "username/test", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("%u/test", "username/test", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern at end */
	rc = mosquitto_sub_matches_acl_with_pattern("test/%u", "test/username", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("test/%u", "test/username", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern in middle */
	rc = mosquitto_sub_matches_acl_with_pattern("test/%u/test", "test/username/test", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("test/%u/test", "test/username/test", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Repeated pattern */
	rc = mosquitto_sub_matches_acl_with_pattern("test/%u/%u/test", "test/username/username/test", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("test/%u/%u/test", "test/username/username/test", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Not a pattern */
	rc = mosquitto_sub_matches_acl_with_pattern("test/%username", "test/username", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Now repeat with wildcards: */

	/* Pattern at beginning */
	rc = mosquitto_sub_matches_acl_with_pattern("%u/test/+", "username/test/+", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("%u/test/+", "username/test/+", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("%u/#", "username/test/+", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("%u/#", "username/test/+", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern at end */
	rc = mosquitto_sub_matches_acl_with_pattern("+/test/%u", "+/test/username", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("+/test/%u", "+/test/username", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern in middle */
	rc = mosquitto_sub_matches_acl_with_pattern("+/%u/test", "test/username/test", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("+/%u/test", "test/username/test", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Repeated pattern */
	rc = mosquitto_sub_matches_acl_with_pattern("+/test/%u/%u/test", "+/test/username/username/test", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("+/test/%u/%u/test", "+/test/username/username/test", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Not a pattern */
	rc = mosquitto_sub_matches_acl_with_pattern("+/test/%username/+", "+/test/username/+", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);
}

static void TEST_acl_pattern_both(void)
{
	int rc;
	bool match;

	/* Sole pattern */
	rc = mosquitto_sub_matches_acl_with_pattern("%u/%c", "username/clientid", "clientid", "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("%u/%c", "username/clientid", "clientid", "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("%u/%c", "username/clientid", "nomatch", "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("%u/%c", "username/clientid", "nomatch", "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Pattern in middle */
	rc = mosquitto_sub_matches_acl_with_pattern("+/test/%c/%u/#", "+/test/clientid/username/test", "clientid", "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("+/test/%c/%u/#", "+/test/clientid/username/test", "clientid", "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("+/test/%c/%u/test", "a/test/clientid/username/test", "nomatch", "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("+/test/%c/%u/test", "a/test/clientid/username/test", "nomatch", "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Repeated pattern */
	rc = mosquitto_sub_matches_acl_with_pattern("test/%u/%c/%c/%u/#", "test/username/clientid/clientid/username/#", "clientid", "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	/* Not a pattern */
	rc = mosquitto_sub_matches_acl_with_pattern("test/%username/+/%client", "test/username/a/clientid", "clientid", "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Not a pattern */
	rc = mosquitto_sub_matches_acl_with_pattern("test/a%u/+/a%c", "test/ausername/a/aclientid", "clientid", "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);
}

static void TEST_acl_pattern_wildcard(void)
{
	int rc;
	bool match;

	/* Malicious */
	/* ========= */

	/* / in client id */
	rc = mosquitto_sub_matches_acl_with_pattern("%c", "clientid/test", "clientid/test", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("%c", "/", "/", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* / in username */
	rc = mosquitto_sub_matches_acl_with_pattern("%u", "username/test", NULL, "username/test", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("%u", "/", NULL, "/", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* + in client id */
	rc = mosquitto_sub_matches_acl_with_pattern("%c", "clientid", "+", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("%c", "+", "+", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* + in username */
	rc = mosquitto_sub_matches_acl_with_pattern("username/%u/+", "username/test/+", NULL, "+", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("username/%u/+", "username/+/+", NULL, "+", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("username/%u/+", "username/+", NULL, "+/a", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* # in client id */
	rc = mosquitto_sub_matches_acl_with_pattern("%c", "#", "#", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* # in username */
	rc = mosquitto_sub_matches_acl_with_pattern("%u", "#", NULL, "#", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Valid */
	/* ========= */

	/* Ends in + */
	rc = mosquitto_sub_matches_acl_with_pattern("clientid/%c/+", "clientid/test/topic", "test", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("clientid/%c/+", "clientid/test/topic", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("username/%u/+", "username/test/topic", NULL, "test", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("username/%u/+", "username/test/topic", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	/* Ends in # */
	rc = mosquitto_sub_matches_acl_with_pattern("+/clientid/%c/#", "+/clientid/test/topic", "test", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("+/clientid/%c/#", "+/clientid/test/topic", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("+/username/%u/#", "+/username/test/topic", NULL, "test", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("+/username/%u/#", "+/username/test/topic", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("+/clientid/%c/#", "+/clientid/test", "test", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("+/clientid/%c/#", "+/clientid/test", "nomatch", NULL, &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl_with_pattern("+/pattern/%u/#", "+/pattern/username", NULL, "username", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl_with_pattern("+/username/%u/#", "+/username/test", NULL, "nomatch", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);
}


static void TEST_acl_pattern_wildcard_wildcard(void)
{
	int rc;
	bool match;

	rc = mosquitto_sub_matches_acl("$SYS/#", "$SYS/broker/#", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl("$SYS/#", "$SYS/+/#", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl("$SYS/#", "$SYS", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, true);

	rc = mosquitto_sub_matches_acl("$SYS/+", "$SYS/#", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl("$SYS/+/a", "$SYS/a/+", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl("$SYS/+", "$SYS/+/a", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl("$SYS/broker/uptime", "$SYS/broker/#", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);

	rc = mosquitto_sub_matches_acl("#", "$SYS/broker/#", &match);
	CU_ASSERT_EQUAL(rc, MOSQ_ERR_SUCCESS);
	CU_ASSERT_EQUAL(match, false);
}

/* ========================================================================
 * PUB TOPIC CHECK
 * ======================================================================== */

static void pub_topic_helper(const char *topic, int rc_expected)
{
	int rc;

	rc = mosquitto_pub_topic_check(topic);
	CU_ASSERT_EQUAL(rc, rc_expected);

	rc = mosquitto_pub_topic_check2(topic, strlen(topic));
	CU_ASSERT_EQUAL(rc, rc_expected);
}

static void TEST_pub_topic_valid(void)
{
	pub_topic_helper("pub/topic", MOSQ_ERR_SUCCESS);
	pub_topic_helper("pub//topic", MOSQ_ERR_SUCCESS);
	pub_topic_helper("pub/ /topic", MOSQ_ERR_SUCCESS);
}

static void TEST_pub_topic_invalid(void)
{
	pub_topic_helper("+pub/topic", MOSQ_ERR_INVAL);
	pub_topic_helper("pub+/topic", MOSQ_ERR_INVAL);
	pub_topic_helper("pub/+topic", MOSQ_ERR_INVAL);
	pub_topic_helper("pub/topic+", MOSQ_ERR_INVAL);
	pub_topic_helper("pub/topic/+", MOSQ_ERR_INVAL);
	pub_topic_helper("#pub/topic", MOSQ_ERR_INVAL);
	pub_topic_helper("pub#/topic", MOSQ_ERR_INVAL);
	pub_topic_helper("pub/#topic", MOSQ_ERR_INVAL);
	pub_topic_helper("pub/topic#", MOSQ_ERR_INVAL);
	pub_topic_helper("pub/topic/#", MOSQ_ERR_INVAL);
	pub_topic_helper("+/pub/topic", MOSQ_ERR_INVAL);
}


/* ========================================================================
 * SUB TOPIC CHECK
 * ======================================================================== */

static void sub_topic_helper(const char *topic, int rc_expected)
{
	int rc;

	rc = mosquitto_sub_topic_check(topic);
	CU_ASSERT_EQUAL(rc, rc_expected);

	rc = mosquitto_sub_topic_check2(topic, strlen(topic));
	CU_ASSERT_EQUAL(rc, rc_expected);
}

static void TEST_sub_topic_valid(void)
{
	sub_topic_helper("sub/topic", MOSQ_ERR_SUCCESS);
	sub_topic_helper("sub//topic", MOSQ_ERR_SUCCESS);
	sub_topic_helper("sub/ /topic", MOSQ_ERR_SUCCESS);
	sub_topic_helper("sub/+/topic", MOSQ_ERR_SUCCESS);
	sub_topic_helper("+/+/+", MOSQ_ERR_SUCCESS);
	sub_topic_helper("+", MOSQ_ERR_SUCCESS);
	sub_topic_helper("sub/topic/#", MOSQ_ERR_SUCCESS);
	sub_topic_helper("sub//topic/#", MOSQ_ERR_SUCCESS);
	sub_topic_helper("sub/ /topic/#", MOSQ_ERR_SUCCESS);
	sub_topic_helper("sub/+/topic/#", MOSQ_ERR_SUCCESS);
	sub_topic_helper("+/+/+/#", MOSQ_ERR_SUCCESS);
	sub_topic_helper("#", MOSQ_ERR_SUCCESS);
}

static void TEST_sub_topic_invalid(void)
{
	sub_topic_helper("+sub/topic", MOSQ_ERR_INVAL);
	sub_topic_helper("sub+/topic", MOSQ_ERR_INVAL);
	sub_topic_helper("sub/+topic", MOSQ_ERR_INVAL);
	sub_topic_helper("sub/topic+", MOSQ_ERR_INVAL);
	sub_topic_helper("#sub/topic", MOSQ_ERR_INVAL);
	sub_topic_helper("sub#/topic", MOSQ_ERR_INVAL);
	sub_topic_helper("sub/#topic", MOSQ_ERR_INVAL);
	sub_topic_helper("sub/topic#", MOSQ_ERR_INVAL);
	sub_topic_helper("#/sub/topic", MOSQ_ERR_INVAL);
}

/* ========================================================================
 * SUB MATCHES ACL
 * ======================================================================== */

static void sub_match_test(const char *acl, const char *sub, bool expected, int rc_expected)
{
	bool result;
	int rc;

	rc = mosquitto_sub_matches_acl(acl, sub, &result);
	CU_ASSERT_EQUAL(rc, rc_expected);
	CU_ASSERT_EQUAL(result, expected);
}


static void TEST_sub_match_acl(void)
{
	sub_match_test("foo/+/bar", "foo/#", false, MOSQ_ERR_SUCCESS);
	sub_match_test("foo/+/ba℞/#", "foo/baz/ba℞", true, MOSQ_ERR_SUCCESS);
	sub_match_test("foo/+/ba℞/#", "foo/baz/ba℞/+", true, MOSQ_ERR_SUCCESS);
	sub_match_test("foo/+/ba℞/#", "foo/baz/ba℞/#", true, MOSQ_ERR_SUCCESS);
	sub_match_test("foo/+/ba℞/#", "foo/baz/+/#", false, MOSQ_ERR_SUCCESS);
	sub_match_test("/+//#", "/foo///#", true, MOSQ_ERR_SUCCESS);
	sub_match_test("#", "$SYS/uptime", false, MOSQ_ERR_SUCCESS);
	sub_match_test("$SYS/#", "$SYS/uptime", true, MOSQ_ERR_SUCCESS);
	sub_match_test("$SYS/+/#", "$SYS/uptime", true, MOSQ_ERR_SUCCESS);
	sub_match_test("$SYS/+/#", "$SYS/broker/uptime", true, MOSQ_ERR_SUCCESS);
	sub_match_test("#", "#", true, MOSQ_ERR_SUCCESS);
	sub_match_test("#", "+", true, MOSQ_ERR_SUCCESS);
	sub_match_test("/#", "+", false, MOSQ_ERR_SUCCESS);
	sub_match_test("/#", "/+", true, MOSQ_ERR_SUCCESS);
	sub_match_test("/+", "#", false, MOSQ_ERR_SUCCESS);
	sub_match_test("/+", "+", false, MOSQ_ERR_SUCCESS);
	sub_match_test("+/+", "topic/topic", true, MOSQ_ERR_SUCCESS);
	sub_match_test("+/+", "topic/topic/", false, MOSQ_ERR_SUCCESS);
	sub_match_test("+", "#", false, MOSQ_ERR_SUCCESS);
	sub_match_test("+", "+", true, MOSQ_ERR_SUCCESS);
	sub_match_test("a/b/c/d/e", "a/b/c/d/e", true, MOSQ_ERR_SUCCESS);
	sub_match_test("a/b/ /d/e", "a/b/c/d/e", false, MOSQ_ERR_SUCCESS);
	sub_match_test("a/b/c/d/e", "a/b/c/d/+", false, MOSQ_ERR_SUCCESS);
	sub_match_test("a/b/c/d/+", "a/b/c/d/e", true, MOSQ_ERR_SUCCESS);
	sub_match_test("a/b/c/d/", "a/b/c/d/+", false, MOSQ_ERR_SUCCESS);
	sub_match_test("a/b/c/d/+", "a/b/c/d/", true, MOSQ_ERR_SUCCESS);
}
/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */

int init_util_topic_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("Util topic", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit util topic test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "Matching: Empty input", TEST_empty_input)
			|| !CU_add_test(test_suite, "Matching: Valid matching", TEST_valid_matching)
			|| !CU_add_test(test_suite, "Matching: Valid no matching", TEST_valid_no_matching)
			|| !CU_add_test(test_suite, "Matching: Invalid but matching", TEST_invalid_but_matching)
			|| !CU_add_test(test_suite, "Matching: Invalid", TEST_invalid)
			|| !CU_add_test(test_suite, "Pub topic: Valid", TEST_pub_topic_valid)
			|| !CU_add_test(test_suite, "Pub topic: Invalid", TEST_pub_topic_invalid)
			|| !CU_add_test(test_suite, "Sub topic: Valid", TEST_sub_topic_valid)
			|| !CU_add_test(test_suite, "Sub topic: Invalid", TEST_sub_topic_invalid)
			|| !CU_add_test(test_suite, "Pattern topic: Empty input", TEST_topic_pattern_empty_input)
			|| !CU_add_test(test_suite, "Pattern topic: clientid", TEST_topic_pattern_clientid)
			|| !CU_add_test(test_suite, "Pattern topic: username", TEST_topic_pattern_username)
			|| !CU_add_test(test_suite, "Pattern topic: both", TEST_topic_pattern_both)
			|| !CU_add_test(test_suite, "Pattern topic: wildcard", TEST_topic_pattern_wildcard)
			|| !CU_add_test(test_suite, "Pattern acl: Empty input", TEST_acl_pattern_empty_input)
			|| !CU_add_test(test_suite, "Pattern acl: clientid", TEST_acl_pattern_clientid)
			|| !CU_add_test(test_suite, "Pattern acl: username", TEST_acl_pattern_username)
			|| !CU_add_test(test_suite, "Pattern acl: both", TEST_acl_pattern_both)
			|| !CU_add_test(test_suite, "Pattern acl: wildcard", TEST_acl_pattern_wildcard)
			|| !CU_add_test(test_suite, "Pattern acl: wildcard vs wildcard", TEST_acl_pattern_wildcard_wildcard)
			|| !CU_add_test(test_suite, "Sub matching: Empty input", TEST_sub_match_empty_input)
			|| !CU_add_test(test_suite, "Sub matching: normal", TEST_sub_match_acl)
			){

		printf("Error adding util topic CUnit tests.\n");
		return 1;
	}

	return 0;
}
