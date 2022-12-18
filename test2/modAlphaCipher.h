#pragma once

#include <string>

using namespace std;

class modAlphaCipher
{
private:
	int key;
public:
	modAlphaCipher()=delete; //запретим конструктор без параметров
	modAlphaCipher(string skey); //конструктор для установки ключа
	string encrypt(string open_text); //зашифрование
	string decrypt(string cipher_text);//расшифрование
	void KeyCheck(string skey);
	void LengthCheck(int skey, string stext);
	void TextCheck(string stext);
};

class cipher_error: public std::invalid_argument
{
public:
	explicit cipher_error (const std::string& what_arg):
		std::invalid_argument(what_arg) {}
	explicit cipher_error (const char* what_arg):
		std::invalid_argument(what_arg) {}
};
