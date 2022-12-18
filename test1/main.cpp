#include <UnitTest++/UnitTest++.h>
#include "modAlphaCipher.h"
#include <string>
#include <locale>

std::string RUS (std::string key, std::string text){
	locale loc("ru_RU.UTF-8");
	wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
	return codec.to_bytes(modAlphaCipher(codec.from_bytes(key)).encrypt(codec.from_bytes(text)));
}



SUITE(KeyTest)
{
	TEST(ValidKey) {
		locale loc("ru_RU.UTF-8");
		wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
		CHECK_EQUAL("КЛЮЧКЛ", codec.to_bytes(modAlphaCipher(codec.from_bytes("КЛЮЧ")).encrypt(codec.from_bytes("АААААА"))));
	}
	TEST(LongKey) {
		locale loc("ru_RU.UTF-8");
		wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
		CHECK_EQUAL("КЛЮЧКЛ",codec.to_bytes(modAlphaCipher(codec.from_bytes("КЛЮЧКЛЮЧ")).encrypt(codec.from_bytes("АААААА"))));
	}
	TEST(LowCaseKey) {
		locale loc("ru_RU.UTF-8");
		wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
		CHECK_EQUAL("КЛЮЧКЛ",codec.to_bytes(modAlphaCipher(codec.from_bytes("ключ")).encrypt(codec.from_bytes("АААААА"))));
	}
	TEST(DigitsInKey) {
		locale loc("ru_RU.UTF-8");
		wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
		CHECK_THROW(modAlphaCipher cp(codec.from_bytes("КЛЮЧ1")),cipher_error);
	}
	TEST(PunctuationInKey) {
		locale loc("ru_RU.UTF-8");
		wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
		CHECK_THROW(modAlphaCipher cp(codec.from_bytes("КЛЮЧ!")),cipher_error);
	}
	TEST(WhitespaceInKey) {
		locale loc("ru_RU.UTF-8");
		wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
		CHECK_THROW(modAlphaCipher cp(codec.from_bytes("КЛ ЮЧ")),cipher_error);
	}
	TEST(EmptyKey) {
		locale loc("ru_RU.UTF-8");
		wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
		CHECK_THROW(modAlphaCipher cp(codec.from_bytes("")),cipher_error);
	}
}


struct KeyB_fixture {
modAlphaCipher * p;
KeyB_fixture()
{
locale loc("ru_RU.UTF-8");
wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
p = new modAlphaCipher(codec.from_bytes("Б"));
}
~KeyB_fixture()
{ delete p;
}
};

SUITE(EncryptTest)
{ TEST_FIXTURE(KeyB_fixture, UpCaseString) {
locale loc("ru_RU.UTF-8");
wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
CHECK_EQUAL("ТЫЖЩЭЗЖЖЪЖЮУЙЦНАДЛЙЦХСБОЧФИТЛЙЦВФМПЛЕБГЬРЖКШБЯ",
codec.to_bytes(p->encrypt(codec.from_bytes("СЪЕШЬЖЕЕЩЕЭТИХМЯГКИХФРАНЦУЗСКИХБУЛОКДАВЫПЕЙЧАЮ"))));
}
TEST_FIXTURE(KeyB_fixture, LowCaseString) {
locale loc("ru_RU.UTF-8");
wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
CHECK_EQUAL("ТЫЖЩЭЗЖЖЪЖЮУЙЦНАДЛЙЦХСБОЧФИТЛЙЦВФМПЛЕБГЬРЖКШБЯ",
codec.to_bytes(p->encrypt(codec.from_bytes("съешьжеещеэтихмягкихфранцузскихбулокдавыпейчаю"))));
}
TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
locale loc("ru_RU.UTF-8");
wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
CHECK_EQUAL("ТЫЖЩЭЗЖЖЪЖЮУЙЦНАДЛЙЦХСБОЧФИТЛЙЦВФМПЛЕБГЬРЖКШБЯ",
codec.to_bytes(p->encrypt(codec.from_bytes("Съешь же еще этих мягких французских булок, да выпей чаю!"))));
}
TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
locale loc("ru_RU.UTF-8");
wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
CHECK_EQUAL("ТОПГЬНДПЕПН",
codec.to_bytes(p->encrypt(codec.from_bytes("С новым 2023 годом"))));
}
TEST_FIXTURE(KeyB_fixture, EmptyString) {
locale loc("ru_RU.UTF-8");
wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
CHECK_THROW(p->encrypt(codec.from_bytes("")),cipher_error);
}
TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
locale loc("ru_RU.UTF-8");
wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
CHECK_THROW(p->encrypt(codec.from_bytes("1234+8765=9999")),cipher_error);
}
TEST(MaxShiftKey) {
locale loc("ru_RU.UTF-8");
wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
CHECK_EQUAL("РЩДЧЫЕДДШДЬСЗФЛЮВЙЗФУПЯМХТЖРЙЗФАТКНЙГЯБЪОДИЦЯЭ",
codec.to_bytes(modAlphaCipher(codec.from_bytes("Я")).encrypt(codec.from_bytes("СЪЕШЬЖЕЕЩЕЭТИХМЯГКИХФРАНЦУЗСКИХБУЛОКДАВЫПЕЙЧАЮ"))));
}
}

SUITE(DecryptTest)
{ TEST_FIXTURE(KeyB_fixture, UpCaseString) {
locale loc("ru_RU.UTF-8");
wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
CHECK_EQUAL("СЪЕШЬЖЕЕЩЕЭТИХМЯГКИХФРАНЦУЗСКИХБУЛОКДАВЫПЕЙЧАЮ",
codec.to_bytes(p->decrypt(codec.from_bytes("ТЫЖЩЭЗЖЖЪЖЮУЙЦНАДЛЙЦХСБОЧФИТЛЙЦВФМПЛЕБГЬРЖКШБЯ"))));
}
TEST_FIXTURE(KeyB_fixture, LowerCaseString) {
locale loc("ru_RU.UTF-8");
wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
CHECK_THROW(p->decrypt(codec.from_bytes("тыжЩЭЗЖЖЪЖЮУЙЦНАДЛЙЦХСБОЧФИТЛЙЦВФМПЛЕБГЬРЖКШБЯ")),cipher_error);
}
TEST_FIXTURE(KeyB_fixture, SpaceString) {
locale loc("ru_RU.UTF-8");
wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
CHECK_THROW(p->decrypt(codec.from_bytes("ТЫЖ ЩЭЗЖЖЪ ЖЮУЙЦ НАДЛЙЦ ХСБОЧ Ф ИТЛЙЦВ ФМП ЛЕБГЬР ЖКШ БЯ")),cipher_error);
}
TEST_FIXTURE(KeyB_fixture, NumericString) {
locale loc("ru_RU.UTF-8");
wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
CHECK_THROW(p->decrypt(codec.from_bytes("ТОПГЬН2023ДПЕПН")),cipher_error);
}
TEST_FIXTURE(KeyB_fixture, EmptyString) {
locale loc("ru_RU.UTF-8");
wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
CHECK_THROW(p->decrypt(codec.from_bytes("")),cipher_error);
}
TEST_FIXTURE(KeyB_fixture, PunctString) {
locale loc("ru_RU.UTF-8");
wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
CHECK_THROW(p->decrypt(codec.from_bytes("АОЛД, АОЛАО")),cipher_error);
}
TEST(MaxShiftKey) {
locale loc("ru_RU.UTF-8");
wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
CHECK_EQUAL("СЪЕШЬЖЕЕЩЕЭТИХМЯГКИХФРАНЦУЗСКИХБУЛОКДАВЫПЕЙЧАЮ",
codec.to_bytes(modAlphaCipher(codec.from_bytes("Я")).decrypt(codec.from_bytes("РЩДЧЫЕДДШДЬСЗФЛЮВЙЗФУПЯМХТЖРЙЗФАТКНЙГЯБЪОДИЦЯЭ"))));
}
}

int main(int argc, char **argv)
{
	return UnitTest::RunAllTests();
}
