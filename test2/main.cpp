#include <UnitTest++/UnitTest++.h>
#include "modAlphaCipher.h"
#include <iostream>
#include <string>

using namespace std;


SUITE(KeyTest)
{
	TEST(ValidKey) {
		CHECK_EQUAL("sg*ea*mse", modAlphaCipher("3").encrypt("message"));
	}
	TEST(EmptyKey) {
		CHECK_THROW(modAlphaCipher cp(""),cipher_error);
	}
	TEST(NotNumericKey) {
		CHECK_THROW(modAlphaCipher cp("a3b"),cipher_error);
	}
	TEST(NotPositiveKey) {
		CHECK_THROW(modAlphaCipher cp("-1"),cipher_error);
	}
}

struct Key5_fixture {
	modAlphaCipher * p;
	Key5_fixture()
	{
		p = new modAlphaCipher("5");
	}
	~Key5_fixture()
	{
		delete p;
	}
};




SUITE(encryptTest)
{
	TEST(ValidKeyE) {
		CHECK_EQUAL("mseysgmea",modAlphaCipher("3").encrypt("mymessage"));
	}
	TEST(AnotherKeyE) {
		CHECK_EQUAL("pl*lp*ee!hms",modAlphaCipher("4").encrypt("helpmepls!"));
	}
	TEST_FIXTURE(Key5_fixture, LongKeyE) {
		CHECK_THROW(p->encrypt("secretmsg"),cipher_error);
	}
	TEST_FIXTURE(Key5_fixture, EmtyTextE) {
		CHECK_THROW(p->encrypt(""),cipher_error);
	}
}

SUITE(DecryptTest)
{
	TEST(ValidKeyD) {
		CHECK_EQUAL("mymessage",modAlphaCipher("3").decrypt("mseysgmea"));
	}
	TEST(AnotherKeyD) {
		CHECK_EQUAL("helpmepls!**",modAlphaCipher("4").decrypt("pl*lp*ee!hms"));
	}
	TEST_FIXTURE(Key5_fixture, LongKeyD) {
		CHECK_THROW(p->decrypt("secretmsg"),cipher_error);
	}
	TEST_FIXTURE(Key5_fixture, EmtyTextD) {
		CHECK_THROW(p->decrypt(""),cipher_error);
	}
}

int main()
{
	return UnitTest::RunAllTests();
}
