#include<iostream>
#include<opencv2/imgproc/imgproc.hpp>
#include<opencv2/highgui/highgui.hpp>
#include<time.h>
#include<stdlib.h>
#include <cstring>
#include <fstream>
#include "sha256.h"
#include<vector>
#include <string.h>
#include<bitset>

using namespace std;
using namespace cv;

/*
블록 매트릭스 : 사진을 블록사이즈로 나눈 결과로 얻은 매트리스
ex) 48 x 48 사진을 블록사이즈 16으로 나눈 결과를 블록 매트릭스라 할 때,
	이 때, 이 블록 매트릭스의 행의 개수를 M , 열의 개수를 N
*/


char Lx_arr[32] = { "AKEIDJFIEPWLQIEKRLSOCPDLEKRJSOC" };
char Ly_arr[32] = { "DKELDKCMVKDLSLWKEIRJWLAKDMCKVLD" };
char Rx_arr[32] = { "HELLOMYNAMEISINFORMATIONSYSTEMH" };
char Ry_arr[32] = { "OHKOREAVERYBEAUTIFULOHMYGODGOOD" };

// Sha256을 위한 함수
#pragma region Sha256



const unsigned int SHA256::sha256_k[64] = //UL = uint32
{ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };





void SHA256::transform(const unsigned char *message, unsigned int block_nb)
{
	uint32 w[64];
	uint32 wv[8];
	uint32 t1, t2;
	const unsigned char *sub_block;
	int i;
	int j;
	for (i = 0; i < (int)block_nb; i++) {
		sub_block = message + (i << 6);
		for (j = 0; j < 16; j++) {
			SHA2_PACK32(&sub_block[j << 2], &w[j]);
		}
		for (j = 16; j < 64; j++) {
			w[j] = SHA256_F4(w[j - 2]) + w[j - 7] + SHA256_F3(w[j - 15]) + w[j - 16];
		}
		for (j = 0; j < 8; j++) {
			wv[j] = m_h[j];
		}
		for (j = 0; j < 64; j++) {
			t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
				+ sha256_k[j] + w[j];
			t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
			wv[7] = wv[6];
			wv[6] = wv[5];
			wv[5] = wv[4];
			wv[4] = wv[3] + t1;
			wv[3] = wv[2];
			wv[2] = wv[1];
			wv[1] = wv[0];
			wv[0] = t1 + t2;
		}
		for (j = 0; j < 8; j++) {
			m_h[j] += wv[j];
		}
	}
}

void SHA256::init()
{
	m_h[0] = 0x6a09e667;
	m_h[1] = 0xbb67ae85;
	m_h[2] = 0x3c6ef372;
	m_h[3] = 0xa54ff53a;
	m_h[4] = 0x510e527f;
	m_h[5] = 0x9b05688c;
	m_h[6] = 0x1f83d9ab;
	m_h[7] = 0x5be0cd19;
	m_len = 0;
	m_tot_len = 0;
}

void SHA256::update(const unsigned char *message, unsigned int len)
{
	unsigned int block_nb;
	unsigned int new_len, rem_len, tmp_len;
	const unsigned char *shifted_message;
	tmp_len = SHA224_256_BLOCK_SIZE - m_len;
	rem_len = len < tmp_len ? len : tmp_len;
	memcpy(&m_block[m_len], message, rem_len);
	if (m_len + len < SHA224_256_BLOCK_SIZE) {
		m_len += len;
		return;
	}
	new_len = len - rem_len;
	block_nb = new_len / SHA224_256_BLOCK_SIZE;
	shifted_message = message + rem_len;
	transform(m_block, 1);
	transform(shifted_message, block_nb);
	rem_len = new_len % SHA224_256_BLOCK_SIZE;
	memcpy(m_block, &shifted_message[block_nb << 6], rem_len);
	m_len = rem_len;
	m_tot_len += (block_nb + 1) << 6;
}

void SHA256::final(unsigned char *digest)
{
	unsigned int block_nb;
	unsigned int pm_len;
	unsigned int len_b;
	int i;
	block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9)
		< (m_len % SHA224_256_BLOCK_SIZE)));
	len_b = (m_tot_len + m_len) << 3;
	pm_len = block_nb << 6;
	memset(m_block + m_len, 0, pm_len - m_len);
	m_block[m_len] = 0x80;
	SHA2_UNPACK32(len_b, m_block + pm_len - 4);
	transform(m_block, block_nb);
	for (i = 0; i < 8; i++) {
		SHA2_UNPACK32(m_h[i], &digest[i << 2]);
	}
}

std::string sha256(std::string input)
{
	unsigned char digest[SHA256::DIGEST_SIZE];
	memset(digest, 0, SHA256::DIGEST_SIZE);

	SHA256 ctx = SHA256();
	ctx.init();
	ctx.update((unsigned char*)input.c_str(), input.length());
	ctx.final(digest);

	char buf[2 * SHA256::DIGEST_SIZE + 1];
	buf[2 * SHA256::DIGEST_SIZE] = 0;
	for (int i = 0; i < SHA256::DIGEST_SIZE; i++)
		sprintf(buf + i * 2, "%02x", digest[i]);
	return std::string(buf);
}
#pragma endregion

//모든 Lx 키를 만들어서 string*로 반환하는 함수
string* Create_EncLXKey(int m) {
	string *Lx_Key = new string[m];

	std::string temp = sha256(Lx_arr);
	for (int i = 0; i < m; ++i) {
		Lx_Key[i] = temp;
		temp = sha256(temp);
	}
	return Lx_Key;
}
//모든 Rx 키를 만들어서 string*로 반환하는 함수
string* Create_EncLYKey(int n) {
	string *Ly_Key=new string[n];

	std::string temp = sha256(Ly_arr);
	for (int i = 0; i < n; ++i) {
		Ly_Key[i] = temp;
		temp = sha256(temp);
	}
	return Ly_Key;
}
//모든 Rx 키를 만들어서 string*로 반환하는 함수
string* Create_EncRXKey(int m) {
	string *Rx_Key =new string[m];
	
	std::string temp = sha256(Rx_arr);
	for (int i = 0; i < m; ++i) {
		Rx_Key[i] = temp;
		temp = sha256(temp);
	}
	return Rx_Key;
}
//모든 Ry 키를 만들어서 string*로 반환하는 함수
string* Create_EncRYKey(int n) {
	
	string *Ry_Key = new string[n];

	std::string temp = sha256(Ry_arr);
	for (int i = 0; i < n; ++i) {
		Ry_Key[i] = temp;
		temp = sha256(temp);
	}


	return Ry_Key;
}
//블록에 맞는 lx , ly , rx , ry 키를 입력으로 갖고, sha256을 8번 돌려서 append 한 것을 반환하는 함수
string EncKey(string lx, string ly, string rx, string ry) {
	string tempKey = sha256(lx + ly + rx + ry);
	for (int i = 0; i < 7; i++)	tempKey += sha256(tempKey);
	return tempKey;
}
//string을 bitset 형식으로 바꿔주는 함수
std::bitset<256> to_bitset(std::string s) {
	auto binary = [](char c) {return c == '0' || c == '1'; };
	auto not_binary = [binary](char c) {return !binary(c);  };

	s.erase(std::remove_if(begin(s), end(s), not_binary), end(s));

	return std::bitset<256>(s);
}

// 입력값 : Encryption할 사진 , Lx 키배열 , Rx 키배열 , Ly 키배열 , Ry 키배열 , 블록 매트릭스의 행의 개수 , 블록 매트릭스의 열의 개수
Mat Encryption_Matrix(Mat src,string* LxKey,string* RxKey,string* LyKey,string* RyKey,int M,int N) {
	Mat EncMat = src.clone(); // Encryption될 행력을 만듬
	string* EncBlock = new string[M*N]; // Encryption된 블락들을 저장하는 string 배열 초기화
	int First_count = 0,Second_count = 0;// 블록 카운트를 위한 변수

	// (i,j) : i = row , j = column
	// M : 45 , N : 80

		for (int m = 0; m < M; m++) { // 블록매트릭스의 행만큼 실행되는 함수
			for (int n = 0; n < N; n++) { //블록매트릭스의 열만큼 실행되는 함수 지금까지 M*N번
				string BlockData = ""; // 하나의 블록에 대한 데이터를 저장할 임시 string 변수
				for (int i = 0; i < 16; i++) {
					for (int j = 0; j < 16; j++) 
						BlockData += src.at<uchar>((16 * m) + i, (16 * n) + j);//블록에 대한 데이터를 BlockData에 저장				
				}
				EncBlock[First_count] = (to_bitset(BlockData)^to_bitset(EncKey(LxKey[0], LyKey[0], RxKey[M - m-1], RyKey[N - n-1]))).to_string(); // XOR 연산
				//EncBlock[First_count] = (std::bitset<>(BlockData) ^ std::bitset<2048>(EncKey(LxKey[0], LyKey[0], RxKey[M - m - 1], RyKey[N - n - 1]))).to_string();
				First_count++;
			}
		} 
	
		imwrite("temp.jpeg", EncMat);

		for (int m = 0; m < M; m++) { // row
			for (int n = 0; n < N; n++) { //col
				int tempCount = 0;
				for (int i = 0; i < 16; i++) {
					for (int j = 0; j < 16; j++) {
						EncMat.at<uchar>((16 * m) + i, (16 * n) + j) = EncBlock[Second_count][tempCount];
						tempCount++;
					}
				}
				Second_count++;
			}
		}
		return EncMat;
}


int main()
{
	Mat src,dst,Dec;
	int Block = 16;
	int M, N;

	/// Load an image
	src = imread("dog.jpg", CV_LOAD_IMAGE_GRAYSCALE);
	M = src.rows / Block; // 블록 매트릭스의 행의 개수
	N = src.cols / Block; // 블록 매트릭스의 열의 개수
	cout << "블록매트릭스의 행 : " << M << endl << "블록 매트릭스의 열 : " << N << endl;

	//dst = src.clone();
	if (!src.data)
	{
		return -1;
	}	
	// LX, LY, RX , RY에 맞는 키 배열을 생성하는 곳
	cout << "LX, LY, RX , RY에 맞는 키 배열을 생성하는 곳" << endl;
	string* Lx_key = Create_EncLXKey(M);
	string* Ly_key = Create_EncLYKey(N);
	string* Rx_key = Create_EncRXKey(M);
	string* Ry_key = Create_EncRYKey(N);
	cout << "키 배열 생성 종료" << endl;

	cout << "Encryption 시작" << endl;
	dst = Encryption_Matrix(src, Lx_key, Rx_key, Ly_key, Ry_key,M,N);
	cout << "Encryption 종료" << endl;
	imwrite("dst.jpeg", dst);
	
	return 0;
}


