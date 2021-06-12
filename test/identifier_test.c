
#include <stdlib.h>
#include "unity.h"
#include "../identifier_without_main.h" 
#define DOING_UNIT_TESTS
TEST_SETUP(Sort)
{
}
TEST_TEAR_DOWN(Sort)
{
}

void TestandoValidacaoParaCharDeAOuaAteZOuz_1(void)
{
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_s('A'), "SUCCESS");
}

void TestandoValidacaoParaCharDeAOuaAteZOuz_2(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_s('Z'), "SUCCESS");
}

void TestandoValidacaoParaCharDeAOuaAteZOuz_3(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_s('D'), "SUCCESS");
}

void TestandoValidacaoParaCharDeAOuaAteZOuz_4(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_s('G'), "SUCCESS");
}

void TestandoValidacaoParaCharDeAOuaAteZOuz_5(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_s('Y'), "SUCCESS");
}

void TestandoValidacaoParaCharDeAOuaAteZOuz_6(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_s('W'), "SUCCESS");
}

void TestandoValidacaoParaCharDeAOuaAteZOuz_7(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_s('a'), "SUCCESS");
}

void TestandoValidacaoParaCharDeAOuaAteZOuz_8(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_s('z'), "SUCCESS");
}

void TestandoValidacaoParaCharDeAOuaAteZOuz_9(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_s('d'), "SUCCESS");
}

void TestandoValidacaoParaCharDeAOuaAteZOuz_10(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_s('g'), "SUCCESS");
}

void TestandoValidacaoParaCharDeAOuaAteZOuz_11(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_s('y'), "SUCCESS");
}

void TestandoValidacaoParaCharDeAOuaAteZOuz_12(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_s('w'), "SUCCESS");
}

void TestandoValidacaoParaCharDeAOuaAteZOuz_NumericError(void)
{
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, valid_s('1'), "It is supposed to be a letter and not a number");
}

void TestandoValidacaoParaCharDeAOuaAteZOuz_WordError(void)
{
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, valid_s("Ferias"), "It is supposed to be a letter and not a word");
}

void TestandoValidacaoParaCharDeAOuaAteZOuz_WordError2(void)
{
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, valid_s("feriado"), "It is supposed to be a letter and not a word");
}

void TestandoValidacaoParaCharDeAOuaAteZOuz_FloatNumericError(void)
{
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, valid_s("8.5"), "It is supposed to be a letter and not a float number");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuz_Empty(void)
{
        //TEST_ASSERT_EQUAL_INT_MESSAGE(0, valid_s(''), "It is supposed to have a letter or one number and it is in blanck");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuz_Espaco(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, valid_s(' '), "It is supposed to have a letter or one number and it is in space");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_1(void)
{
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('A'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_2(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('Z'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_3(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('D'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_4(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('G'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_5(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('Y'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_6(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('W'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_7(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('a'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_8(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('z'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_9(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('d'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_10(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('g'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_11(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('y'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_12(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('w'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_13(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('0'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_14(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('9'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_15(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('5'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_16(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('8'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_17(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('2'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_18(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('7'), "SUCCESS");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_Empty(void)
{
        //TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f(''), "It is supposed to have a letter or one number and it is in blanck");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_Espaco(void)
{
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f(' '), "It is supposed to have a letter or one number and it is in space");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_WordError(void)
{
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f("Abobora"), "It is supposed to be a letter or one number and not a word");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_WordError2(void)
{
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f("Orelha"), "It is supposed to be a letter or one number and not a word");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_FloatNumberError(void)
{
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f("5.2"), "It is supposed to be a letter or one number and not a float number");
}

void TestandoValidacaoParaCharAndInteirosDeAOuaAteZOuzEDe0ate9_NumberError(void)
{
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, valid_f('15'), "It is supposed to be a letter or one number and not a two digit number");
}

void TestandoMain_ComecandoComNumero(void){
    int aux;
    aux = system("echo '123oi' | ./identifier");
    TEST_ASSERT_EQUAL_INT_MESSAGE(256, aux, "It is supposed to start with a letter");
}
void TestandoMain_Empty(void){
    int aux;
    aux = system("echo '' | ./identifier");
    TEST_ASSERT_EQUAL_INT_MESSAGE(256, aux, "It is supposed to start with a letter");
}

void TestandoMain_Espaco(void){
    int aux;
    aux = system("echo ' ' | ./identifier");
    TEST_ASSERT_EQUAL_INT_MESSAGE(256, aux, "It is supposed to start with a letter");
}

void TestandoMain_ContendoCaracterEspecial(void){
    int aux;
    aux = system("echo 'oi_12' | ./identifier");
    TEST_ASSERT_EQUAL_INT_MESSAGE(256, aux, "It is supposed to start with a letter");
}

void TestandoMain_ComecandoComLetraSucesso(void){
    int aux;
    aux = system("echo 'oi123' | ./identifier");
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, aux, "It is supposed to  be valid");
}

void TestandoMain_ComecandoComLetraApenasLetrasSucesso(void){
    int aux;
    aux = system("echo 'Yaya' | ./identifier");
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, aux, "It is supposed to be valid");
}

void TestandoMain_ComecandoComLetraComNumerosInvalido(void){
    int aux;
    aux = system("echo 'oi1234' | ./identifier");
    TEST_ASSERT_EQUAL_INT_MESSAGE(256, aux, "It is supposed to have less than or equal to 6 letters and/or numbers");
}

void TestandoMain_ComecandoComLetraApenasLetrasInvalido(void){
    int aux;
    aux = system("echo 'Nedison' | ./identifier");
    TEST_ASSERT_EQUAL_INT_MESSAGE(256, aux, "It is supposed to have less than or equal to 6 letters and/or numbers");
}