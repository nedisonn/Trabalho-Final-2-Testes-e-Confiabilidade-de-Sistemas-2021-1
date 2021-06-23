
#include <stdlib.h>
#include "unity.h"
#include "../src/crypt.h" 
#define DOING_UNIT_TESTS
unsigned int key_4[4] = {
    0x561C204D, 0x2F9CB4DE,
    0x135E4234, 0xECFA1B16
};
unsigned int wrong_key_4[4] = {
    0x561C204D, 0xECFA1B16,
    0x2F9CB4DE, 0x135E4234
};
unsigned int key_6[6] = {
    0x561C204D, 0x2F9CB4DE, 0x135E4234,
    0xECFA1B16, 0xDEADBEEF, 0x01234567
};
unsigned int wrong_key_6[6] = {
    0x01234567, 0x561C204D, 0x135E4234,
    0xECFA1B16, 0xDEADBEEF, 0x2F9CB4DE
};
unsigned int key_8[8] = {
    0x561C204D, 0x2F9CB4DE, 0x135E4234, 0xECFA1B16,
    0x01234567, 0xDEADBEEF, 0x204D561C, 0xB4DE2F9C
};
unsigned int wrong_key_8[8] = {
    0x204D561C, 0x561C204D, 0x135E4234, 0xECFA1B16,
    0x01234567, 0xDEADBEEF, 0x2F9CB4DE, 0xB4DE2F9C
};

unsigned int input[4] = {0x8FB0F364, 0x18144208, 0x15F6BA22, 0x84CD53F2};
unsigned int expected_output_enc_XTEA[4] = {0x90C69105, 0x355FFB82, 0x63A9368B, 0x59BAD548};
unsigned int input_dec_XTEA[4] = {0x90C69105, 0x355FFB82, 0x63A9368B, 0x59BAD548};
unsigned int expected_output_enc_AES_128[4] = {0x14EEA43A, 0xD8B0688D, 0xD186E267, 0xA27C9E5C};
unsigned int input_dec_AES_128[4] = {0x14EEA43A, 0xD8B0688D, 0xD186E267, 0xA27C9E5C};
unsigned int expected_output_enc_AES_192[4] = {0xFCA729F0, 0x9521D7E4, 0x772CFB5A, 0x1A9C5423};
unsigned int input_dec_AES_192[4] = {0xFCA729F0, 0x9521D7E4, 0x772CFB5A, 0x1A9C5423};
unsigned int expected_output_enc_AES_256[4] = {0xC8A17B7A, 0x562700BA, 0xD799BEF9, 0x5B0A3D43};
unsigned int input_dec_AES_256[4] = {0xC8A17B7A, 0x562700BA, 0xD799BEF9, 0x5B0A3D43};
unsigned int expected_output_enc_BLOWFISH_128[4] = {0xC835AFD0, 0x09BCAAC3, 0x55CDF1B2, 0x84E309AD};
unsigned int input_dec_BLOWFISH_128[4] = {0xC835AFD0, 0x09BCAAC3, 0x55CDF1B2, 0x84E309AD};
unsigned int expected_output_enc_BLOWFISH_192[4] = {0x4BC146F3, 0x4BC63DF1, 0x8C098F9D, 0x9C16BC7D};
unsigned int input_dec_BLOWFISH_192[4] = {0x4BC146F3, 0x4BC63DF1, 0x8C098F9D, 0x9C16BC7D};
unsigned int expected_output_enc_BLOWFISH_256[4] = {0x4B733E3C, 0x24723D9E, 0xE4C45938, 0x2A33634D};
unsigned int input_dec_BLOWFISH_256[4] = {0x4B733E3C, 0x24723D9E, 0xE4C45938, 0x2A33634D};
unsigned int expected_output_dec[4] = {0x8FB0F364, 0x18144208, 0x15F6BA22, 0x84CD53F2};


//Testes de Sucessos
void TestingEncryptionXTEA_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4,(uint32_t *) input, 0, 1, (uint32_t *) (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_XTEA, output, 4, "True is expected.");
}

void TestingEncryptionAES128_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4,(uint32_t *) input, 1, 1, (uint32_t *) (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_128, output, 4, "True is expected.");
}

void TestingEncryptionAES192_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_6,(uint32_t *) input, 2, 1, (uint32_t *) (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_192, output, 4, "True is expected.");
}

void TestingEncryptionAES256_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_8,(uint32_t *) input, 3, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_256, output, 4, "True is expected.");
}

void TestingEncryptionBLOWFISH128_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4,(uint32_t *) input, 4, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_128, output, 4, "True is expected.");
}

void TestingEncryptionBLOWFISH192_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_6,(uint32_t *) input, 5, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_192, output, 4, "True is expected.");
}

void TestingEncryptionBLOWFISH256_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_8,(uint32_t *) input, 6, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_256, output, 4, "True is expected.");
}

void TestingDecryptionionXTEA_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4, (uint32_t *) input_dec_XTEA, 0, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "True is expected.");
}

void TestingDecryptionAES128_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4, (uint32_t *) input_dec_AES_128, 1, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "True is expected.");
}

void TestingDecryptionAES192_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_6, (uint32_t *) input_dec_AES_192, 2, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "True is expected.");
}

void TestingDecryptionAES256_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_8, (uint32_t *) input_dec_AES_256, 3, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "True is expected.");
}

void TestingDecryptionBLOWFISH128_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4, (uint32_t *) input_dec_BLOWFISH_128, 4, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "True is expected.");
}

void TestingDecryptionBLOWFISH192_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_6, (uint32_t *) input_dec_BLOWFISH_192, 5, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "True is expected.");
}

void TestingDecryptionBLOWFISH256_SUCESS(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_8, (uint32_t *) input_dec_BLOWFISH_256, 6, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "True is expected.");
}

//Testes com falhas -- XTEA
void TestingEncryptionXTEA_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_4,(uint32_t *) input, 0, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_XTEA, output, 4, "FAIL is expected.");
}

void TestingDecryptionXTEA_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_4, (uint32_t *) input_dec_XTEA, 0, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionXTEA_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4, (uint32_t *) input_dec_XTEA, 0, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_XTEA, output, 4, "FAIL is expected.");
}

void TestingDecryptionXTEA_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4,(uint32_t *) input, 0, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionXTEA_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4,(uint32_t *) input, 4, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_XTEA, output, 4, "FAIL is expected.");
}

void TestingDecryptionXTEA_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4, (uint32_t *) input_dec_XTEA, 1, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

//Testes com falhas -- AES-128
void TestingEncryptionAES128_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_4,(uint32_t *) input, 1, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_128, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES128_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_4, (uint32_t *) input_dec_AES_128, 1, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionAES128_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4, (uint32_t *) input_dec_AES_128, 1, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_128, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES128_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4,(uint32_t *) input, 1, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionAES128_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4,(uint32_t *) input, 4, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_128, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES128_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4, (uint32_t *) input_dec_AES_128, 0, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

//Testes com falhas -- AES-192
void TestingEncryptionAES192_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_6,(uint32_t *) input, 2, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_192, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES192_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_6, (uint32_t *) input_dec_AES_192, 2, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionAES192_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_6, (uint32_t *) input_dec_AES_192, 2, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_192, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES192_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_6,(uint32_t *) input, 2, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionAES192_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_6,(uint32_t *) input, 5, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_192, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES192_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_6, (uint32_t *) input_dec_AES_192, 5, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

//Testes com falhas -- AES-256
void TestingEncryptionAES256_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_8,(uint32_t *) input, 3, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_256, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES256_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_8, (uint32_t *) input_dec_AES_256, 3, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionAES256_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_8, (uint32_t *) input_dec_AES_256, 3, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_256, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES256_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_8,(uint32_t *) input, 3, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionAES256_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_8,(uint32_t *) input, 6, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_AES_256, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES256_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_8, (uint32_t *) input_dec_AES_256, 6, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

//Testes com falhas -- BLOWFISH-128
void TestingEncryptionBLOWFISH128_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_4,(uint32_t *) input, 4, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_128, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH128_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_4, (uint32_t *) input_dec_BLOWFISH_128, 4, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionBLOWFISH128_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4, (uint32_t *) input_dec_BLOWFISH_128, 4, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_128, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH128_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4,(uint32_t *) input, 4, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionBLOWFISH128_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4,(uint32_t *) input, 1, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_128, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH128_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4, (uint32_t *) input_dec_BLOWFISH_128, 0, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

//Testes com falhas -- BLOWFISH-192
void TestingEncryptionBLOWFISH192_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_6,(uint32_t *) input, 5, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_192, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH192_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_6, (uint32_t *) input_dec_BLOWFISH_192, 5, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionBLOWFISH192_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_6, (uint32_t *) input_dec_BLOWFISH_192, 5, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_192, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH192_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_6,(uint32_t *) input, 5, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionBLOWFISH192_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_6,(uint32_t *) input, 2, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_192, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH192_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_6, (uint32_t *) input_dec_BLOWFISH_192, 2, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

//Testes com falhas -- BLOWFISH-256
void TestingEncryptionBLOWFISH256_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_8,(uint32_t *) input, 4, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_256, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH256_FAILWrongKey(void)
{
    unsigned int output[4] = {};
    crypt(wrong_key_8, (uint32_t *) input_dec_BLOWFISH_256, 4, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionBLOWFISH256_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_8, (uint32_t *) input_dec_BLOWFISH_256, 4, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_256, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH256_FAILWrongInput(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_8,(uint32_t *) input, 4, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionBLOWFISH256_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_8,(uint32_t *) input, 3, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_256, output, 4, "FAIL is expected.");
}

void TestingDecryptionBLOWFISH256_FAILWrongType(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_8, (uint32_t *) input_dec_BLOWFISH_256, 3, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

//Teste falha type & dec_enc limite
void TestingEncryptionBLOWFISH256_FAILTypeDontExist_MaiorQue6(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_8,(uint32_t *) input, 7, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_256, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES192_FAILTypeDontExist_MenorQue0(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_6, (uint32_t *) input_dec_AES_192, -1, 0, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionXTEA_FAILTypeDontExist_Float(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_4,(uint32_t *) input, (uint8_t) 2.5, 1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_XTEA, output, 4, "FAIL is expected.");
}

void TestingEncryptionBLOWFISH128_FAILEncDecDontExist_MaiorQue1(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *)key_4, (uint32_t *)input, 4, 2, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_128, output, 4, "FAIL is expected.");
}

void TestingDecryptionAES256_FAILEncDecDontExist_MenorQue0(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_8, (uint32_t *) input_dec_AES_256, 3, -1, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_dec, output, 4, "FAIL is expected.");
}

void TestingEncryptionBLOWFISH192_FAILEncDecDontExist_Float(void)
{
    unsigned int output[4] = {};
    crypt((uint32_t *) key_6,(uint32_t *) input, 5, (uint8_t) 0.6, (uint32_t *) output);

    TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected_output_enc_BLOWFISH_192, output, 4, "FAIL is expected.");
}