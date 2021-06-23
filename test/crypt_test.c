
#include <stdlib.h>
#include "unity.h"
#include "../src/crypt.h" 
#define DOING_UNIT_TESTS
const unsigned int key_4[4] = {
    0x561C204DL, 0x2F9CB4DEL,
    0x135E4234L, 0xECFA1B16L
};
const unsigned int wrong_key_4[4] = {
    0x561C204DL, 0xECFA1B16L,
    0x2F9CB4DEL, 0x135E4234L
};
const unsigned int key_6[6] = {
    0x561C204DL, 0x2F9CB4DEL, 0x135E4234L,
    0xECFA1B16L, 0xDEADBEEFL, 0x01234567L
};
const unsigned int wrong_key_6[6] = {
    0x01234567L, 0x561C204DL, 0x135E4234L,
    0xECFA1B16L, 0xDEADBEEFL, 0x2F9CB4DEL
};
const unsigned int key_8[8] = {
    0x561C204DL, 0x2F9CB4DEL, 0x135E4234L, 0xECFA1B16L,
    0x01234567L, 0xDEADBEEFL, 0x204D561CL, 0xB4DE2F9CL
};
const unsigned int wrong_key_8[8] = {
    0x204D561CL, 0x561C204DL, 0x135E4234L, 0xECFA1B16L,
    0x01234567L, 0xDEADBEEFL, 0x2F9CB4DEL, 0xB4DE2F9CL
};

const unsigned int input[4] = {0x8FB0F364L, 0x18144208L, 0x15F6BA22L, 0x84CD53F2L};
const unsigned int expected_output_enc_XTEA[4] = {0x90C69105L, 0x355FFB82L, 0x63A9368BL, 0x59BAD548L};
const unsigned int input_dec_XTEA[4] = {0x90C69105L, 0x355FFB82L, 0x63A9368BL, 0x59BAD548L};
const unsigned int expected_output_enc_AES_128[4] = {0x14EEA43AL, 0xD8B0688DL, 0xD186E267L, 0xA27C9E5CL};
const unsigned int input_dec_AES_128[4] = {0x14EEA43AL, 0xD8B0688DL, 0xD186E267L, 0xA27C9E5CL};
const unsigned int expected_output_enc_AES_192[4] = {0xFCA729F0L, 0x9521D7E4L, 0x772CFB5AL, 0x1A9C5423L};
const unsigned int input_dec_AES_192[4] = {0xFCA729F0L, 0x9521D7E4L, 0x772CFB5AL, 0x1A9C5423L};
const unsigned int expected_output_enc_AES_256[4] = {0xC8A17B7AL, 0x562700BAL, 0xD799BEF9L, 0x5B0A3D43L};
const unsigned int input_dec_AES_256[4] = {0xC8A17B7AL, 0x562700BAL, 0xD799BEF9L, 0x5B0A3D43L};
const unsigned int expected_output_enc_BLOWFISH_128[4] = {0xC835AFD0L, 0x09BCAAC3L, 0x55CDF1B2L, 0x84E309ADL};
const unsigned int input_dec_BLOWFISH_128[4] = {0xC835AFD0L, 0x09BCAAC3L, 0x55CDF1B2L, 0x84E309ADL};
const unsigned int expected_output_enc_BLOWFISH_192[4] = {0x4BC146F3L, 0x4BC63DF1L, 0x8C098F9DL, 0x9C16BC7DL};
const unsigned int input_dec_BLOWFISH_192[4] = {0x4BC146F3L, 0x4BC63DF1L, 0x8C098F9DL, 0x9C16BC7DL};
const unsigned int expected_output_enc_BLOWFISH_256[4] = {0x4B733E3CL, 0x24723D9EL, 0xE4C45938L, 0x2A33634DL};
const unsigned int input_dec_BLOWFISH_256[4] = {0x4B733E3CL, 0x24723D9EL, 0xE4C45938L, 0x2A33634DL};
const unsigned int expected_output_dec[4] = {0x8FB0F364L, 0x18144208L, 0x15F6BA22L, 0x84CD53F2L};


//Testes de Sucessos
void TestingEncryptionXTEA_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input, 0, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_XTEA, output, 4, "True is expected.");
}

void TestingEncryptionAES128_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input, 1, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_128, output, 4, "True is expected.");
}

void TestingEncryptionAES192_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt(key_6, input, 2, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_192, output, 4, "True is expected.");
}

void TestingEncryptionAES256_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt(key_8, input, 3, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_256, output, 4, "True is expected.");
}

void TestingEncryptionBLOWFISH128_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input, 4, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_128, output, 4, "True is expected.");
}

void TestingEncryptionBLOWFISH192_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt(key_6, input, 5, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_192, output, 4, "True is expected.");
}

void TestingEncryptionBLOWFISH256_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt(key_8, input, 6, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_256, output, 4, "True is expected.");
}

void TestingDecryptionionXTEA_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input_dec_XTEA, 0, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "True is expected.");
}

void TestingDecryptionAES128_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input_dec_AES_128, 1, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "True is expected.");
}

void TestingDecryptionAES192_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt(key_6, input_dec_AES_192, 2, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "True is expected.");
}

void TestingDecryptionAES256_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt(key_8, input_dec_AES_256, 3, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "True is expected.");
}

void TestingDecryptionBLOWFISH128_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input_dec_BLOWFISH_128, 4, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "True is expected.");
}

void TestingDecryptionBLOWFISH192_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt(key_6, input_dec_BLOWFISH_192, 5, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "True is expected.");
}

void TestingDecryptionBLOWFISH256_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt(key_8, input_dec_BLOWFISH_256, 6, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "True is expected.");
}

//Testes com falhas -- XTEA
void TestingEncryptionXTEA_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_4, input, 0, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_XTEA, output, 4, "FAIL is expected.");
}

void TestingDecryptionXTEA_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_4, input_dec_XTEA, 0, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionXTEA_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input_dec_XTEA, 0, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_XTEA, output, 4, "FAIL is expected.");
}

void TestingDecryptionXTEA_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input, 0, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionXTEA_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input, 4, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_XTEA, output, 4, "FAIL is expected.");
}

void TestingDecryptionXTEA_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input_dec_XTEA, 1, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

//Testes com falhas -- AES-128
void TestingEncryptionAES128_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_4, input, 1, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_128, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES128_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_4, input_dec_AES_128, 1, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionAES128_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input_dec_AES_128, 1, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_128, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES128_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input, 1, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionAES128_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input, 4, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_128, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES128_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input_dec_AES_128, 0, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

//Testes com falhas -- AES-192
void TestingEncryptionAES192_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_6, input, 2, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_192, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES192_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_6, input_dec_AES_192, 2, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionAES192_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt(key_6, input_dec_AES_192, 2, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_192, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES192_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt(key_6, input, 2, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionAES192_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt(key_6, input, 5, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_192, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES192_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt(key_6, input_dec_AES_192, 5, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

//Testes com falhas -- AES-256
void TestingEncryptionAES256_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_8, input, 3, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_256, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES256_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_8, input_dec_AES_256, 3, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionAES256_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt(key_8, input_dec_AES_256, 3, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_256, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES256_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt(key_8, input, 3, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionAES256_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt(key_8, input, 6, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_256, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES256_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt(key_8, input_dec_AES_256, 6, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

//Testes com falhas -- BLOWFISH-128
void TestingEncryptionBLOWFISH128_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_4, input, 4, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_128, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH128_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_4, input_dec_BLOWFISH_128, 4, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionBLOWFISH128_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input_dec_BLOWFISH_128, 4, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_128, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH128_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input, 4, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionBLOWFISH128_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input, 1, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_128, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH128_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input_dec_BLOWFISH_128, 0, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

//Testes com falhas -- BLOWFISH-192
void TestingEncryptionBLOWFISH192_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_6, input, 5, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_192, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH192_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_6, input_dec_BLOWFISH_192, 5, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionBLOWFISH192_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt(key_6, input_dec_BLOWFISH_192, 5, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_192, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH192_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt(key_6, input, 5, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionBLOWFISH192_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt(key_6, input, 2, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_192, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH192_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt(key_6, input_dec_BLOWFISH_192, 2, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

//Testes com falhas -- BLOWFISH-256
void TestingEncryptionBLOWFISH256_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_8, input, 4, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_256, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH256_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_8, input_dec_BLOWFISH_256, 4, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionBLOWFISH256_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt(key_8, input_dec_BLOWFISH_256, 4, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_256, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH256_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt(key_8, input, 4, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionBLOWFISH256_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt(key_8, input, 3, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_256, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH256_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt(key_8, input_dec_BLOWFISH_256, 3, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

//Teste falha type & dec_enc limite
void TestingEncryptionBLOWFISH256_FAILTypeDontExist_MaiorQue6(void)
{
    unsigned int output[4] = {};
    crypt(key_8, input, 7, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_256, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES192_FAILTypeDontExist_MenorQue0(void)
{
    unsigned int output[4] = {};
    crypt(key_6, input_dec_AES_192, -1, 0, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionXTEA_FAILTypeDontExist_Float(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input, 2.5, 1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_XTEA, output, 4, "FAIL is expected.");
}

void TestingEncryptionBLOWFISH128_FAILEncDecDontExist_MaiorQue1(void)
{
    unsigned int output[4] = {};
    crypt(key_4, input, 4, 2, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_128, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES256_FAILEncDecDontExist_MenorQue0(void)
{
    unsigned int output[4] = {};
    crypt(key_8, input_dec_AES_256, 3, -1, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionBLOWFISH192_FAILEncDecDontExist_Float(void)
{
    unsigned int output[4] = {};
    crypt(key_6, input, 5, 0.6, output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_192, output, 4, "FAIL is expected.");
}