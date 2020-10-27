#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "mosquitto.h"

/* Test data taken from
 * http://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt but modified for
 * updated standard (no 5, 6 byte lengths) */

static void utf8_helper_len(const char *text, int len, int expected)
{
	int result;

	result = mosquitto_validate_utf8(text, len);
	CU_ASSERT_EQUAL(result, expected);
}

static void utf8_helper(const char *text, int expected)
{
	utf8_helper_len(text, (int)strlen(text), expected);
}


static void TEST_utf8_empty(void)
{
	utf8_helper_len(NULL, 0, MOSQ_ERR_INVAL);
}


static void TEST_utf8_valid(void)
{
	/* 1  Some correct UTF-8 text */
	utf8_helper("", MOSQ_ERR_SUCCESS);
	utf8_helper("You should see the Greek word 'kosme':       \"Œ∫·ΩπœÉŒºŒµ\"", MOSQ_ERR_SUCCESS);
}


static void TEST_utf8_truncated(void)
{
	uint8_t buf[4];

	/* As per boundary condition tests, but less one character */
	buf[0] = 0xC2; buf[1] = 0;
	utf8_helper((char *)buf, MOSQ_ERR_MALFORMED_UTF8);

	buf[0] = 0xE0; buf[1] = 0xA0; buf[2] = 0;
	utf8_helper((char *)buf, MOSQ_ERR_MALFORMED_UTF8);

	buf[0] = 0xF0; buf[1] = 0x90; buf[2] = 0x80; buf[3] = 0;
	utf8_helper((char *)buf, MOSQ_ERR_MALFORMED_UTF8);
}


static void TEST_utf8_boundary_conditions(void)
{
	/* 2  Boundary condition test cases */
	/* 2.1  First possible sequence of a certain length */
	utf8_helper_len("2.1.1  1 byte  (U-00000000):        \"\0\"", 39, MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("2.1.2  2 bytes (U-00000080):        \"¬Ä\"", MOSQ_ERR_MALFORMED_UTF8); /* control char */
	utf8_helper("2.1.3  3 bytes (U-00000800):        \"‡†Ä\"", MOSQ_ERR_SUCCESS);
	utf8_helper("2.1.4  4 bytes (U-00010000):        \"êÄÄ\"", MOSQ_ERR_SUCCESS);

	/* 2.2  Last possible sequence of a certain length */

	utf8_helper("2.2.1  1 byte  (U-0000007F):        \"\"", MOSQ_ERR_MALFORMED_UTF8); /* control char */
	utf8_helper("2.2.2  2 bytes (U-000007FF):        \"ﬂø\"", MOSQ_ERR_SUCCESS);
	/* Non character */
	utf8_helper("2.2.3  3 bytes (U-0000FFFF):        \"Ôøø\"", MOSQ_ERR_MALFORMED_UTF8);
	/* Non character */
	utf8_helper("2.2.4  4 bytes (U-0010FFFF):        \"˜øøø\"", MOSQ_ERR_MALFORMED_UTF8);

	/* 2.3  Other boundary conditions */

	utf8_helper("2.3.1  U-0000D7FF = ed 9f bf = \"Ìüø\"", MOSQ_ERR_SUCCESS);
	utf8_helper("2.3.2  U-0000E000 = ee 80 80 = \"ÓÄÄ\"", MOSQ_ERR_SUCCESS);
	utf8_helper("2.3.3  U-0000FFFD = ef bf bd = \"ÔøΩ\"", MOSQ_ERR_SUCCESS);
	/* Non character */
	utf8_helper("2.3.4  U-0010FFFF = f4 8f bf bf = \"Ùèøø\"", MOSQ_ERR_MALFORMED_UTF8);
	/* This used to be valid in pre-2003 utf-8 */
	utf8_helper("2.3.5  U-00110000 = f4 90 80 80 = \"ÙêÄÄ\"", MOSQ_ERR_MALFORMED_UTF8);
}


static void TEST_utf8_malformed_sequences(void)
{
	uint8_t buf[100];
	int i;
	/* 3  Malformed sequences */
	/* 3.1  Unexpected continuation bytes */
	utf8_helper("3.1.1  First continuation byte 0x80: \"Ä\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.1.2  Last  continuation byte 0xbf: \"ø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.1.3  2 continuation bytes: \"Äø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.1.4  3 continuation bytes: \"ÄøÄ\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.1.5  4 continuation bytes: \"ÄøÄø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.1.6  5 continuation bytes: \"ÄøÄøÄ\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.1.7  6 continuation bytes: \"ÄøÄøÄø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.1.8  7 continuation bytes: \"ÄøÄøÄøÄ\"", MOSQ_ERR_MALFORMED_UTF8);

	/* 3.1.9  Sequence of all 64 possible continuation bytes (0x80-0xbf): */
	memset(buf, 0, sizeof(buf));
	for(i=0x80; i<0x90; i++){
		buf[i-0x80] = (uint8_t)i;
	}
	utf8_helper((char *)buf, MOSQ_ERR_MALFORMED_UTF8);
	memset(buf, 0, sizeof(buf));
	for(i=0x90; i<0xa0; i++){
		buf[i-0x90] = (uint8_t)i;
	}
	utf8_helper((char *)buf, MOSQ_ERR_MALFORMED_UTF8);

	for(i=0x80; i<0xA0; i++){
		buf[0] = (uint8_t)i;
		buf[1] = 0;
		utf8_helper((char *)buf, MOSQ_ERR_MALFORMED_UTF8);
	}

	for(i=0xA0; i<0xC0; i++){
		buf[0] = (uint8_t)i;
		buf[1] = 0;
		utf8_helper((char *)buf, MOSQ_ERR_MALFORMED_UTF8);
	}

	/* 3.2  Lonely start characters */

	/* 3.2.1  All 32 first bytes of 2-byte sequences (0xc0-0xdf),
       each followed by a space character: */
	utf8_helper("¿ ¡ ¬ √ ƒ ≈ ∆ « » …   À Ã Õ Œ œ – — “ ” ‘ ’ ÷ ◊ ÿ Ÿ ⁄ € ‹ › ﬁ ﬂ ", MOSQ_ERR_MALFORMED_UTF8);
	for(i=0xC0; i<0xE0; i++){
		buf[0] = (uint8_t)i;
		buf[1] = ' ';
		buf[2] = 0;
		utf8_helper((char *)buf, MOSQ_ERR_MALFORMED_UTF8);
	}

	/* 3.2.2  All 16 first bytes of 3-byte sequences (0xe0-0xef),
       each followed by a space character: */
	utf8_helper("\"‡ · ‚ „ ‰ Â Ê Á Ë È Í Î Ï Ì Ó Ô \"", MOSQ_ERR_MALFORMED_UTF8);
	for(i=0xe0; i<0xf0; i++){
		buf[0] = (uint8_t)i;
		buf[1] = ' ';
		buf[2] = 0;
		utf8_helper((char *)buf, MOSQ_ERR_MALFORMED_UTF8);
	}

	/* 3.2.3  All 8 first bytes of 4-byte sequences (0xf0-0xf7),
       each followed by a space character: */
	utf8_helper("\" Ò Ú Û Ù ı ˆ ˜ \"", MOSQ_ERR_MALFORMED_UTF8);
	for(i=0xF0; i<0xF8; i++){
		buf[0] = (uint8_t)i;
		buf[1] = ' ';
		buf[2] = 0;
		utf8_helper((char *)buf, MOSQ_ERR_MALFORMED_UTF8);
	}

	/* 3.2.4  All 4 first bytes of 5-byte sequences (0xf8-0xfb),
       each followed by a space character: */
	utf8_helper("\"¯ ˘ ˙ ˚ \"", MOSQ_ERR_MALFORMED_UTF8);
	for(i=0xF8; i<0xFC; i++){
		buf[0] = (uint8_t)i;
		buf[1] = ' ';
		buf[2] = 0;
		utf8_helper((char *)buf, MOSQ_ERR_MALFORMED_UTF8);
	}

	/* 3.2.5  All 2 first bytes of 6-byte sequences (0xfc-0xfd),
       each followed by a space character: */
	utf8_helper("\"¸ ˝ \"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("¸ ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("˝ ", MOSQ_ERR_MALFORMED_UTF8);
	for(i=0xFC; i<0xFE; i++){
		buf[0] = (uint8_t)i;
		buf[1] = ' ';
		buf[2] = 0;
		utf8_helper((char *)buf, MOSQ_ERR_MALFORMED_UTF8);
	}

	/* 3.3  Sequences with last continuation byte missing

	All bytes of an incomplete sequence should be signalled as a single
	malformed sequence, i.e., you should see only a single replacement
	character in each of the next 10 tests. (Characters as in section 2) */

	utf8_helper("3.3.1  2-byte sequence with last byte missing (U+0000):     \"¿\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.3.2  3-byte sequence with last byte missing (U+0000):     \"‡Ä\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.3.3  4-byte sequence with last byte missing (U+0000):     \"ÄÄ\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.3.4  5-byte sequence with last byte missing (U+0000):     \"¯ÄÄÄ\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.3.5  6-byte sequence with last byte missing (U+0000):     \"¸ÄÄÄÄ\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.3.6  2-byte sequence with last byte missing (U-000007FF): \"ﬂ\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.3.7  3-byte sequence with last byte missing (U-0000FFFF): \"Ôø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.3.8  4-byte sequence with last byte missing (U-001FFFFF): \"˜øø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.3.9  5-byte sequence with last byte missing (U-03FFFFFF): \"˚øøø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.3.10 6-byte sequence with last byte missing (U-7FFFFFFF): \"˝øøøø\"", MOSQ_ERR_MALFORMED_UTF8);

	/* 3.4  Concatenation of incomplete sequences

		All the 10 sequences of 3.3 concatenated, you should see 10 malformed
		sequences being signalled:*/

	utf8_helper("\"¿‡ÄÄÄ¯ÄÄÄ¸ÄÄÄÄﬂÔø˜øø˚øøø˝øøøø\"", MOSQ_ERR_MALFORMED_UTF8);

	/* 3.5  Impossible bytes

		The following two bytes cannot appear in a correct UTF-8 string */

	utf8_helper("3.5.1  fe = \"˛\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.5.2  ff = \"ˇ\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("3.5.3  fe fe ff ff = \"˛˛ˇˇ\"", MOSQ_ERR_MALFORMED_UTF8);
}

static void TEST_utf8_overlong_encoding(void)
{
	/* 4  Overlong sequences

		The following sequences are not malformed according to the letter of
		the Unicode 2.0 standard. However, they are longer then necessary and
		a correct UTF-8 encoder is not allowed to produce them. A "safe UTF-8
		decoder" should reject them just like malformed sequences for two
		reasons: (1) It helps to debug applications if overlong sequences are
		not treated as valid representations of characters, because this helps
		to spot problems more quickly. (2) Overlong sequences provide
		alternative representations of characters, that could maliciously be
		used to bypass filters that check only for ASCII characters. For
		instance, a 2-byte encoded line feed (LF) would not be caught by a
		line counter that counts only 0x0a bytes, but it would still be
		processed as a line feed by an unsafe UTF-8 decoder later in the
		pipeline. From a security point of view, ASCII compatibility of UTF-8
		sequences means also, that ASCII characters are *only* allowed to be
		represented by ASCII bytes in the range 0x00-0x7f. To ensure this
		aspect of ASCII compatibility, use only "safe UTF-8 decoders" that
		reject overlong UTF-8 sequences for which a shorter encoding exists. */

	/* 4.1  Examples of an overlong ASCII character

		With a safe UTF-8 decoder, all of the following five overlong
		representations of the ASCII character slash ("/") should be rejected
		like a malformed UTF-8 sequence, for instance by substituting it with
		a replacement character. If you see a slash below, you do not have a
		safe UTF-8 decoder! */

	utf8_helper("4.1.1 U+002F = c0 af             = \"¿Ø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("4.1.2 U+002F = e0 80 af          = \"‡ÄØ\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("4.1.3 U+002F = f0 80 80 af       = \"ÄÄØ\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("4.1.4 U+002F = f8 80 80 80 af    = \"¯ÄÄÄØ\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("4.1.5 U+002F = fc 80 80 80 80 af = \"¸ÄÄÄÄØ\"", MOSQ_ERR_MALFORMED_UTF8);

	/* 4.2  Maximum overlong sequences

		Below you see the highest Unicode value that is still resulting in an
		overlong sequence if represented with the given number of bytes. This
		is a boundary test for safe UTF-8 decoders. All five characters should
		be rejected like malformed UTF-8 sequences. */

	utf8_helper("4.2.1  U-0000007F = c1 bf             = \"¡ø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("4.2.2  U-000007FF = e0 9f bf          = \"‡üø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("4.2.3  U-0000FFFF = f0 8f bf bf       = \"èøø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("4.2.4  U-001FFFFF = f8 87 bf bf bf    = \"¯áøøø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("4.2.5  U-03FFFFFF = fc 83 bf bf bf bf = \"¸Éøøøø\"", MOSQ_ERR_MALFORMED_UTF8);

	/* 4.3  Overlong representation of the NUL character

		The following five sequences should also be rejected like malformed
		UTF-8 sequences and should not be treated like the ASCII NUL
		character. */

	utf8_helper("4.3.1  U+0000 = c0 80             = \"¿Ä\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("4.3.2  U+0000 = e0 80 80          = \"‡ÄÄ\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("4.3.3  U+0000 = f0 80 80 80       = \"ÄÄÄ\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("4.3.4  U+0000 = f8 80 80 80 80    = \"¯ÄÄÄÄ\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("4.3.5  U+0000 = fc 80 80 80 80 80 = \"¸ÄÄÄÄÄ\"", MOSQ_ERR_MALFORMED_UTF8);
}


static void TEST_utf8_illegal_code_positions(void)
{
	/* 5  Illegal code positions

		The following UTF-8 sequences should be rejected like malformed
		sequences, because they never represent valid ISO 10646 characters and
		a UTF-8 decoder that accepts them might introduce security problems
		comparable to overlong UTF-8 sequences. */

	/* 5.1 Single UTF-16 surrogates */

	utf8_helper("5.1.1  U+D800 = ed a0 80 = \"Ì†Ä\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("5.1.2  U+DB7F = ed ad bf = \"Ì≠ø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("5.1.3  U+DB80 = ed ae 80 = \"ÌÆÄ\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("5.1.4  U+DBFF = ed af bf = \"ÌØø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("5.1.5  U+DC00 = ed b0 80 = \"Ì∞Ä\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("5.1.6  U+DF80 = ed be 80 = \"ÌæÄ\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("5.1.7  U+DFFF = ed bf bf = \"Ìøø\"", MOSQ_ERR_MALFORMED_UTF8);

	/* 5.2 Paired UTF-16 surrogates */

	utf8_helper("5.2.1  U+D800 U+DC00 = ed a0 80 ed b0 80 = \"Ì†ÄÌ∞Ä\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("5.2.2  U+D800 U+DFFF = ed a0 80 ed bf bf = \"Ì†ÄÌøø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("5.2.3  U+DB7F U+DC00 = ed ad bf ed b0 80 = \"Ì≠øÌ∞Ä\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("5.2.4  U+DB7F U+DFFF = ed ad bf ed bf bf = \"Ì≠øÌøø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("5.2.5  U+DB80 U+DC00 = ed ae 80 ed b0 80 = \"ÌÆÄÌ∞Ä\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("5.2.6  U+DB80 U+DFFF = ed ae 80 ed bf bf = \"ÌÆÄÌøø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("5.2.7  U+DBFF U+DC00 = ed af bf ed b0 80 = \"ÌØøÌ∞Ä\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("5.2.8  U+DBFF U+DFFF = ed af bf ed bf bf = \"ÌØøÌøø\"", MOSQ_ERR_MALFORMED_UTF8);

	/* 5.3 Noncharacter code positions

		The following "noncharacters" are "reserved for internal use" by
		applications, and according to older versions of the Unicode Standard
		"should never be interchanged". Unicode Corrigendum #9 dropped the
		latter restriction. Nevertheless, their presence in incoming UTF-8 data
		can remain a potential security risk, depending on what use is made of
		these codes subsequently. Examples of such internal use:

		- Some file APIs with 16-bit characters may use the integer value -1
		= U+FFFF to signal an end-of-file (EOF) or error condition.

		- In some UTF-16 receivers, code point U+FFFE might trigger a
		byte-swap operation (to convert between UTF-16LE and UTF-16BE).

		With such internal use of noncharacters, it may be desirable and safer
		to block those code points in UTF-8 decoders, as they should never
		occur legitimately in incoming UTF-8 data, and could trigger unsafe
		behaviour in subsequent processing.

		Particularly problematic noncharacters in 16-bit applications: */
	utf8_helper("5.3.1  U+FFFE = ef bf be = \"Ôøæ\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("5.3.2  U+FFFF = ef bf bf = \"Ôøø\"", MOSQ_ERR_MALFORMED_UTF8);

	/* Other noncharacters: */

	/* FIXME - these need splitting up into separate tests. */
	utf8_helper("5.3.3  U+FDD0 .. U+FDEF = \"Ô∑êÔ∑ëÔ∑íÔ∑ìÔ∑îÔ∑ïÔ∑ñÔ∑óÔ∑òÔ∑ôÔ∑öÔ∑õÔ∑úÔ∑ùÔ∑ûÔ∑üÔ∑†Ô∑°Ô∑¢Ô∑£Ô∑§Ô∑•Ô∑¶Ô∑ßÔ∑®Ô∑©Ô∑™Ô∑´Ô∑¨Ô∑≠Ô∑ÆÔ∑Ø\"", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑ê", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑ë", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑í", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑ì", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑î", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑ï", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑ñ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑ó", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑ò", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑ô", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑ö", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑õ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑ú", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑ù", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑û", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑ü", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑†", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑°", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑¢", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑£", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑§", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑•", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑¶", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑ß", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑®", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑©", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑™", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑´", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑¨", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑≠", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑Æ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ô∑Ø", MOSQ_ERR_MALFORMED_UTF8);

	/* 5.3.4  U+nFFFE U+nFFFF (for n = 1..10) */

	utf8_helper("üøæ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("üøø", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Øøæ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Øøø", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("øøæ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("øøø", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Òèøæ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Òèøø", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Òüøæ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Òüøø", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("ÒØøæ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("ÒØøø", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Òøøæ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Òøøø", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Úèøæ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Úèøø", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Úüøæ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Úüøø", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("ÚØøæ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("ÚØøø", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Úøøæ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Úøøø", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ûèøæ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ûèøø", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ûüøæ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ûüøø", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("ÛØøæ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("ÛØøø", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ûøøæ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ûøøø", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ùèøæ", MOSQ_ERR_MALFORMED_UTF8);
	utf8_helper("Ùèøø", MOSQ_ERR_MALFORMED_UTF8);
}


void TEST_utf8_control_characters(void)
{
	uint8_t buf[10];
	int i;

	/* U+0001 to U+001F are single byte control characters */
	for(i=0x01; i<0x20; i++){
		buf[0] = (uint8_t)i;
		buf[1] = '\0';
		utf8_helper((char *)buf, MOSQ_ERR_MALFORMED_UTF8);
	}

	/* U+007F is a single byte control character */
	buf[0] = 0x7F;
	buf[1] = '\0';
	utf8_helper((char *)buf, MOSQ_ERR_MALFORMED_UTF8);

	/* U+007F to U+009F are two byte control characters */
	for(i=0x80; i<0xA0; i++){
		buf[0] = 0xC2;
		buf[1] = (uint8_t)(i-0x80);
		buf[2] = '\0';
		utf8_helper((char *)buf, MOSQ_ERR_MALFORMED_UTF8);
	}

}


void TEST_utf8_mqtt_1_5_4_2(void)
{
	uint8_t buf[10] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', '\0'};

	utf8_helper_len((char *)buf, 9, MOSQ_ERR_SUCCESS);

	buf[3] = '\0';
	utf8_helper_len((char *)buf, 9, MOSQ_ERR_MALFORMED_UTF8);
}


void TEST_utf8_mqtt_1_5_4_3(void)
{
	uint8_t buf[10] = {'a', 'b', 0xEF, 0xBB, 0xBF, 'f', 'g', 'h', 'i', '\0'};

	utf8_helper_len((char *)buf, 9, MOSQ_ERR_SUCCESS);
}


/* ========================================================================
 * TEST SUITE SETUP
 * ======================================================================== */

int init_utf8_tests(void)
{
	CU_pSuite test_suite = NULL;

	test_suite = CU_add_suite("UTF-8", NULL, NULL);
	if(!test_suite){
		printf("Error adding CUnit test suite.\n");
		return 1;
	}

	if(0
			|| !CU_add_test(test_suite, "UTF-8 empty", TEST_utf8_empty)
			|| !CU_add_test(test_suite, "UTF-8 valid", TEST_utf8_valid)
			|| !CU_add_test(test_suite, "UTF-8 truncated", TEST_utf8_truncated)
			|| !CU_add_test(test_suite, "UTF-8 boundary conditions", TEST_utf8_boundary_conditions)
			|| !CU_add_test(test_suite, "UTF-8 malformed sequences", TEST_utf8_malformed_sequences)
			|| !CU_add_test(test_suite, "UTF-8 overlong encoding", TEST_utf8_overlong_encoding)
			|| !CU_add_test(test_suite, "UTF-8 illegal code positions", TEST_utf8_illegal_code_positions)
			|| !CU_add_test(test_suite, "UTF-8 control characters", TEST_utf8_control_characters)
			|| !CU_add_test(test_suite, "UTF-8 MQTT-1.5.4-2", TEST_utf8_mqtt_1_5_4_2)
			|| !CU_add_test(test_suite, "UTF-8 MQTT-1.5.4-3", TEST_utf8_mqtt_1_5_4_3)
			){

		printf("Error adding UTF-8 CUnit tests.\n");
		return 1;
	}

	return 0;
}


