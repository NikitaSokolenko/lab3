#include <iostream>
#include <string>
#include "modAlphaCipher.h"
#include <typeinfo>



using namespace std;

modAlphaCipher::modAlphaCipher(string skey)
{
	KeyCheck(skey);
	key = stoi(skey);
}


string modAlphaCipher::encrypt(string open_text)
{
    TextCheck(open_text);
	LengthCheck(key,open_text);
	int t_key = key;
	if (open_text.size() % key != 0) {
		for (unsigned long  int i=1; i<=(key - (open_text.size() % key)+1); i++) {
			open_text.push_back('*');
		}
		//cout<<open_text<<endl;
	}
	string work = "";
	for (int i=0; i<key; i++) {
		for (unsigned long int j=0; j<(open_text.size() / key); j++) {
			work.push_back(open_text[t_key-1]);
			t_key +=key;
		}
		t_key = key-i-1;
	}
	return work;
}


string modAlphaCipher::decrypt(string cipher_text)
{
	TextCheck(cipher_text);
	LengthCheck(key,cipher_text);
	int t_key = cipher_text.size() / key;
	string work = "";
	for (unsigned long int i=0; i<(cipher_text.size() / key); i++) {
		for (int j=0; j<key; j++) {
			work.push_back(cipher_text[cipher_text.size() - t_key]);
			t_key += cipher_text.size() / key;
		}
		t_key = cipher_text.size() / key-i-1;
	}
	return work;
}

inline void modAlphaCipher::KeyCheck(string skey)
{
		if (skey.empty()) {
			throw cipher_error(std::string("Invalid key Empty"));
		}
		for (auto c : skey) {
			if (!isdigit(c)) {
				throw cipher_error(std::string("Invalid key NaN"));
			}
		}
		if (stoi(skey) < 1) {
			throw cipher_error(std::string("Invalid key Negative"));
		}
}

inline void modAlphaCipher::LengthCheck(int skey, string stext)
{
		if (stext.size()/2 < skey) {
			throw cipher_error(std::string("Key is too long"));
		}
}

inline void modAlphaCipher::TextCheck(string stext)
{
	
		if (stext.empty()) {
			throw cipher_error(std::string("Empty message"));
		}
}
