#include <vector>
#include <string>
#include <map>
#include <codecvt>
#include <cstdlib>
#include <locale>
#include "modAlphaCipher.h"
#include <iostream>
using namespace std;

modAlphaCipher::modAlphaCipher(const std::wstring& skey)
{
	locale loc("ru_RU.UTF-8");
	wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
	wnumAlpha = codec.from_bytes(numAlpha);
	for (unsigned i=0; i<numAlpha.size(); i++) {
		alphaNum[wnumAlpha[i]]=i;
	}
    alphaNum.erase(alphaNum.begin());
	key = convert(getValidKey(skey));
}

std::wstring modAlphaCipher::encrypt(const std::wstring& open_text)
{
	locale loc("ru_RU.UTF-8");
	wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
	std::vector<int> work = convert(getValidOpenText(open_text));
	for(unsigned i=0; i < work.size(); i++) {
		work[i] = (work[i] + key[i % key.size()]) % alphaNum.size();
	}
	return convert(work);
}

std::wstring modAlphaCipher::decrypt(const std::wstring& cipher_text)
{
	locale loc("ru_RU.UTF-8");
	wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
	std::vector<int> work = convert(getValidCipherText(cipher_text));
	for(unsigned i=0; i < work.size(); i++) {
		work[i] = (work[i] + alphaNum.size() - key[i % key.size()]) % alphaNum.size();

	}
	return convert(work);
}

inline std::vector<int> modAlphaCipher::convert(const std::wstring& s)
{
	locale loc("ru_RU.UTF-8");
	wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
	std::vector<int> result;
	for(auto c:s) {
		result.push_back(alphaNum[c]);
	}
	return result;
}
inline std::wstring modAlphaCipher::convert(const std::vector<int>& v)
{
	locale loc("ru_RU.UTF-8");
	wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
	std::wstring result;
	for(auto i:v) {
		result.push_back(wnumAlpha[i]);
	}
	return result;
}

inline std::wstring modAlphaCipher::getValidKey(const std::wstring& s)
{
	if (s.empty())
		throw cipher_error("Empty key");
	locale loc("ru_RU.UTF-8");
	wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
	std::wstring tmp(s);
	for (auto & c:tmp) {
		if (!isalpha(c, loc)) {
			std::string ts = codec.to_bytes(s);
			throw cipher_error(std::string("Invalid key ")+ts);
		}
		if (islower(c, loc))
			c = toupper(c, loc);
	}
	return tmp;
}

inline std::wstring modAlphaCipher::getValidOpenText(const std::wstring & s)
{
	locale loc("ru_RU.UTF-8");
	wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
	std::wstring tmp;
	for (auto & c:s) {
		if (isalpha(c,loc)) {
			if (islower(c,loc))
				tmp.push_back(toupper(c,loc));
			else
				tmp.push_back(c);
		}
	}
	if (tmp.empty())
		throw cipher_error("Empty open text");
	return tmp;
}

inline std::wstring modAlphaCipher::getValidCipherText(const std::wstring & s)
{
	locale loc("ru_RU.UTF-8");
	wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
	if (s.empty())
		throw cipher_error("Empty cipher text");
	for (auto c:s) {
		if (!isalpha(c,loc)) {
			std::string ts = codec.to_bytes(s);
			throw cipher_error(std::string("Invalid cipher text ")+ts);
		}
		if (!isupper(c,loc)){
		std::string ts = codec.to_bytes(s);
			throw cipher_error(std::string("Invalid cipher text ")+ts);
		}
	}
	return s;
}
