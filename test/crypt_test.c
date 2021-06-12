
#include <stdlib.h>
#include "unity.h"
#include "../src/crypt.h" 
#define DOING_UNIT_TESTS
TEST_SETUP(Sort)
{
}
TEST_TEAR_DOWN(Sort)
{
}

const unsigned int key_4[4] = {
    0xDEADBEEFL, 0x01234567L,
    0x89ABCDEFL, 0xDEADBEEFL
};
const unsigned int key_6[6] = {
    0xDEADBEEFL, 0x01234567L, 0x89ABCDEFL,
    0xDEADBEEFL, 0xDEADBEEFL, 0xDEADBEEFL
};
const unsigned int key_8[8] = {
    0xDEADBEEFL, 0x01234567L, 0x89ABCDEFL, 0xDEADBEEFL,
    0xDEADBEEFL, 0x01234567L, 0x89ABCDEFL, 0xDEADBEEFL
};

const unsigned int plan[4] = {0xA5A5A5A5L, 0x01234567L, 0xFEDCBA98L, 0x5A5A5A5AL};

void TestandoValidacaoParaCharDeAOuaAteZOuz_1(void)
{
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_s('A'), "SUCCESS");
}
void TestandoMain_ComecandoComLetraApenasLetrasInvalido(void){
    int aux;
    aux = system("echo 'Nedison' | ./identifier");
    TEST_ASSERT_EQUAL_INT_MESSAGE(256, aux, "It is supposed to have less than or equal to 6 letters and/or numbers");
}