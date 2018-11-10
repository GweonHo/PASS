#include<iostream>
#include<opencv2/imgproc/imgproc.hpp>
#include<opencv2/highgui/highgui.hpp>
#include<time.h>
#include<stdlib.h>
#include <cstring>
#include <fstream>
#include "sha256.h"
#include<vector>
#include<string.h>
#include<bitset>
#include<ctime>
#include<cstdlib>

using namespace std;
using namespace cv;




string EncKey(string lx, string ly, string rx, string ry);
Mat Encryption_Matrix(Mat src, string* LxKey, string* RxKey, string* LyKey, string* RyKey, int M, int N, int BlockSize);
string* Create_EncLXKey(int n, string Lx);
string* Create_EncLYKey(int m, string Ly);
string* Create_EncRXKey(int n, string Rx);
string* Create_EncRYKey(int m, string Ry);
string Create_Specific_Location_Key(string Msk, int Location);
string* CropKeyGen(int M, int N, int Left_M, int Left_N, int Right_M, int Right_N, string Lx_Msk, string Ly_Msk, string Rx_Msk, string Ry_Msk);
Mat Decryption(Mat EncSrc, int M, int N, string* DecKeyGroup, int BlockSize, int Left_M, int Left_N, int Right_M, int Right_N);
string HexToASCII(string hex);
string EncKey(string lx, string ly, string rx, string ry);

//TODO
// �̹��� ����� BlockSize�� ����� �ƴϰ� �ణ�� ���̰� ���� ��� ���̰� ���� �κ��� ENC�� ���� �ʴ´�.
// ����ȭ �� �� �ִ� �κ� ����� ����


/*
��� ��Ʈ���� : ������ ��ϻ������ ���� ����� ���� ��Ʈ����
ex) 48 x 48 ������ ��ϻ����� 16���� ���� ����� ��� ��Ʈ������ �� ��,
	�� ��, �� ��� ��Ʈ������ ���� ������ M , ���� ������ N
*/



// Sha256�� ���� �Լ�
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

#pragma region Ű �迭 �����ϴ� �� - �� ����ȭ ��ų �� ����

//��� Lx Ű�� ���� string*�� ��ȯ�ϴ� �Լ�
string* Create_EncLXKey(int n,string Lx) {
	string *Lx_Key = new string[n];

	std::string temp = sha256(Lx);
	for (int i = 0; i < n; i++) {
		Lx_Key[i] = temp;
		temp = sha256(temp);
	}
	return Lx_Key;
}
//��� Rx Ű�� ���� string*�� ��ȯ�ϴ� �Լ�
string* Create_EncLYKey(int m,string Ly) {
	string *Ly_Key=new string[m];

	std::string temp = sha256(Ly);
	for (int i = 0; i < m; i++) {
		Ly_Key[i] = temp;
		temp = sha256(temp);
	}
	return Ly_Key;
}
//��� Rx Ű�� ���� string*�� ��ȯ�ϴ� �Լ�
string* Create_EncRXKey(int n,string Rx) {
	string *Rx_Key =new string[n];
	
	std::string temp = sha256(Rx);
	if (n == 0) {
		Rx_Key[0] = temp;
	}
	else {
		for (int i = 0; i < n; i++) {
			Rx_Key[i] = temp;
			temp = sha256(temp);
		}
	}
	
	return Rx_Key;
}
//��� Ry Ű�� ���� string*�� ��ȯ�ϴ� �Լ�
string* Create_EncRYKey(int m,string Ry) {
	
	string *Ry_Key = new string[m];
	std::string temp = sha256(Ry);
	if (m == 0) {
		Ry_Key[0] = temp;
	}
	else {
		for (int i = 0; i < m; i++) {
			Ry_Key[i] = temp;
			temp = sha256(temp);
		}
	}
	
	return Ry_Key;
}

#pragma endregion

#pragma region Dec Key �迭 ���� �� ���� �Լ� - �� ����ȭ ����
//Lx , Ly�� �����ؼ� ����ڰ� Dec�ϰ� ���� ���� DecKey �����ϴ� �Լ�
string Create_Specific_Location_Key_L(string Msk, int Location) {
	string Spec_key = sha256(Msk); // Lx_Key[0] , Ly_Key[0]
	for (int i = 0; i < Location; i++) {
		Spec_key = sha256(Spec_key);		
	}

	return Spec_key;
}
//Rx�� �����ؼ� ����ڰ� Dec�ϰ� ���� ���� DecKey �����ϴ� �Լ�
string Create_Specific_Location_Key_Rx(string Msk, int Location,int N) {
	string Spec_key = sha256(Msk); // Rx_Key[0]
	for (int i = 0; i < N-Location; i++) {// i < 12
		Spec_key = sha256(Spec_key);
	}

	return Spec_key;
}
//Ry�� �����ؼ� ����ڰ� Dec�ϰ� ���� ���� DecKey �����ϴ� �Լ�
string Create_Specific_Location_Key_Ry(string Msk, int Location,int M) {
	string Spec_key = sha256(Msk); // Ry_Key[0]
	for (int i = 0; i < M-Location; i++) {
		Spec_key = sha256(Spec_key);
	}

	return Spec_key;
}
#pragma endregion

// Decryption�Լ����� CropKeyGen�Լ��� ���ؼ� ���� ��°��� ���ؼ� �ʿ��� DecKey���� ����� ��ȯ�ϴ� �Լ�
// ex. ������� �Է��� 0 0 5 6�̸� Lx�� �������� Lx_key[0]~Lx_Key[N]���� ���� ��ȯ��
string* CreateKeyArray(int len, string Key) {
	string* KeyArray = new string[len];
	KeyArray[0] = Key;
	for (int i = 1; i < len; i++) {
		KeyArray[i] = sha256(KeyArray[i-1]);
	}
	return KeyArray;
}

// Decryption�� ������ �簢������ �������� ��
// �簢�� ���� �� �𼭸��� �ִ� ����� (M,N)�� ���� Left_M , Left_N
// �簢�� ������ �� �𼭸��� �ִ� ����� (M',N')�� ���� Right_M , Right_N
string* CropKeyGen(int M, int N, int Left_M, int Left_N, int Right_M, int Right_N , string Lx_Msk , string Ly_Msk,string Rx_Msk, string Ry_Msk) {
	string* DecKeyGroup = new string[4];
	DecKeyGroup[0] = Create_Specific_Location_Key_L(Lx_Msk, Left_N); //  Lx�� �ش�
	DecKeyGroup[1] = Create_Specific_Location_Key_L(Ly_Msk, Left_M); // Ly�� �ش�
	DecKeyGroup[2] = Create_Specific_Location_Key_Rx(Rx_Msk, Right_N,N); // Rx�� �ش�
	DecKeyGroup[3] = Create_Specific_Location_Key_Ry(Ry_Msk, Right_M,M); // Ry�� �ش�

	cout << "LX_KEY : " << DecKeyGroup[0] << endl;
	cout << "LY_KEY : " << DecKeyGroup[1] << endl;
	cout << "RX_KEY : " << DecKeyGroup[2] << endl;
	cout << "RY_KEY : " << DecKeyGroup[3] << endl;

	return DecKeyGroup;
}

Mat Decryption(Mat EncSrc, int M, int N, string* DecKeyGroup, int BlockSize, int Left_M, int Left_N, int Right_M, int Right_N) {
	Mat DecSrc = EncSrc.clone();
	string* Dec_LxKey, *Dec_LyKey, *Dec_RxKey, *Dec_RyKey;
	/*
		����
		M : 10 N : 18
		Left_N : 0 , Left_M : 0
		Right_N : 6 , Right_M : 5
	*/
	Dec_LxKey = CreateKeyArray(N-Left_N, DecKeyGroup[0]); // Dec_LxKey�� ũ�� : 18 - 0 = 18
	Dec_LyKey = CreateKeyArray(M-Left_M, DecKeyGroup[1]); // Dec_LxKey�� ũ�� : 10 - 0 = 10
	Dec_RxKey = CreateKeyArray(Right_N, DecKeyGroup[2]); // Dec_LxKey�� ũ�� :  6
	Dec_RyKey = CreateKeyArray(Right_M, DecKeyGroup[3]); // Dec_LxKey�� ũ�� :  5

	for (int i = 0; i < Right_M; i++) { // i�� 0���� 4���� ����
		for (int j = 0; j < Right_N; j++) { // j�� 0���� 5���� ����
			int count = 0;
			string EncKeyData = EncKey(Dec_LxKey[j], Dec_LyKey[i], Dec_RxKey[Right_N - j -1], Dec_RyKey[Right_M - i -1]);
			
			for (int row = 0; row < BlockSize; row++) {
				for (int col = 0; col < BlockSize; col++) {
					DecSrc.at<uchar>(((BlockSize*(Left_M + i)) + row), ((BlockSize*(Left_N + j)) + col)) ^= EncKeyData[count];
					count++;
				}
			}
			cout << "ENCKEY �Ķ���͵� LX , LY , RX , RY : " << j << " " << i << " " << Right_N - j - 1 << " " << Right_M - i - 1 << endl;
			cout << "[M,N] ------------  [" << (Left_M + i) << "," << (Left_N + j) << "]" << endl;
		}
	}
	return DecSrc;
}

//Hex string�� ASCII string���� �ٲٴ� �Լ�
string HexToASCII(string hex)
{
	int len = hex.length();
	std::string newString;
	for (int i = 0; i< len; i += 2)
	{
		string byte = hex.substr(i, 2);//�Է� ���� hex String�� 2���� �ɰ��� ��
		char chr = (char)(int)strtol(byte.c_str(), NULL, 16);// ASCII�� ��ȯ�ϴ� �� 
		newString += chr; //newString�� ��ȯ�ϴ� ���� ����
	}
	return newString;
}

//��Ͽ� �´� lx , ly , rx , ry Ű�� �Է����� ����, sha256�� 8�� ������ append �� ���� ��ȯ�ϴ� �Լ�
string EncKey(string lx, string ly, string rx, string ry) {
	std::string tempKey = sha256(lx + ly + rx + ry);
	for (int i = 0; i < 7; i++)	
		tempKey += sha256(tempKey);
	//sha256�Լ��� ������ ���� ������� hex string�̾ HexToASCII�Լ��� ����
	string EncKey = HexToASCII(tempKey); 

	return EncKey;
}

// �Է°� : Encryption�� ���� , Lx Ű�迭 , Rx Ű�迭 , Ly Ű�迭 , Ry Ű�迭 , ��� ��Ʈ������ ���� ���� , ��� ��Ʈ������ ���� ����
Mat Encryption_Matrix(Mat src,string* LxKey,string* RxKey,string* LyKey,string* RyKey,int M,int N,int BlockSize) {
	Mat EncMat = src.clone(); // Encryption�� ������ ���� ���
	
		for (int m = 0; m < M; m++) { // ��ϸ�Ʈ������ �ุŭ ����Ǵ� �Լ�
			for (int n = 0; n < N; n++) { //��ϸ�Ʈ������ ����ŭ ����Ǵ� �Լ� ���ݱ��� M*N��
				string BlockData = ""; // �ϳ��� ��Ͽ� ���� �����͸� ������ �ӽ� string ����
				for (int i = 0; i < BlockSize; i++) {
					for (int j = 0; j < BlockSize; j++) 
						BlockData += src.at<uchar>((BlockSize * m) + i, (BlockSize * n) + j);//��Ͽ� ���� �����͸� BlockData�� ����				
				}
				
				string EncKeyData = EncKey(LxKey[n], LyKey[m], RxKey[N - n - 1], RyKey[M - m - 1]);//��Ͽ� �´� Encryption Ű �����Ͽ� ����
				int count = 0;
				for (int block_row = 0; block_row < BlockSize; block_row++) {
					for (int block_col = 0; block_col < BlockSize; block_col++) {
						EncMat.at<uchar>((BlockSize * m) + block_row, (BlockSize * n) + block_col) = BlockData[count] ^ EncKeyData[count];// XOR�ϴ� �κ�
						count++;
					}
				}
			}
		} 
	return EncMat;
}

int main()
{
	char Lx_arr[32] = { "AK12rsc9320dkcvc9d02k2d2j230dkC" };
	char Ly_arr[32] = { "dfldje230idkdvj39wodkdjv023kfjk" };
	char Rx_arr[32] = { "sdfj3k2d9fslkgadkjSDEdvkej23l9c" };
	char Ry_arr[32] = { "DJflkf320fdkvj12e1lkvcv9woq3kzd" };

	Mat src,dst,Dec;
	int BlockSize = 16;
	int M, N;
	int Left_N, Left_M , Right_N,Right_M;
	
	/// Load an image
	src = imread("lion.jpg", CV_LOAD_IMAGE_GRAYSCALE);
	M = src.rows / BlockSize; // ��� ��Ʈ������ ���� ����
	N = src.cols / BlockSize; // ��� ��Ʈ������ ���� ����
	cout << "��� ��Ʈ������ �� - M : " << M << endl << "��� ��Ʈ������ �� - N : "<< N << endl<<endl;
	cout << " src�� �� - M' : " << src.rows << endl << " src�� �� - N' : " << src.cols << endl << endl;
	if (!src.data)
	{
		return -1;
	}	
	// LX, LY, RX , RY�� �´� Ű �迭�� �����ϴ� ��
	cout << "LX, LY, RX , RY�� �´� Ű �迭�� �����ϴ� ��" << endl;
	string* Lx_key = Create_EncLXKey(N,Lx_arr);
	string* Ly_key = Create_EncLYKey(M,Ly_arr);
	string* Rx_key = Create_EncRXKey(N,Rx_arr);
	string* Ry_key = Create_EncRYKey(M,Ry_arr);
	cout << "Ű �迭 ���� ����" << endl;

	cout << "Lx_Key ó�� : " <<Lx_key[0] << endl;
	cout << "Ly_Key ó�� : " << Ly_key[0] << endl;
	cout << "Rx_Key ó�� : " << Rx_key[0] << endl;
	cout << "Ry_Key ó�� : " << Ry_key[0] << endl;
	
#pragma region Encryption �κ�
	cout << "Encryption ����" << endl<<endl;
	dst = Encryption_Matrix(src, Lx_key, Rx_key, Ly_key, Ry_key,M,N,BlockSize);
	imwrite("Enc_lion_Block16.jpeg", dst);
	cout << "Encryption ����" << endl<<endl;
#pragma endregion

#pragma region Decryption �κ�
	cout << "Decryption" << endl << "Decryption �� ����"<<endl<<"���� �� �� ����� ��(M)�� ��(N)\n������ �� �� ����� ��(M')�� ��(N')\n�Է� ����(ex. 2 3 4 5 , M'>M and N'>N)" << endl;

	cin >> Left_M >> Left_N >> Right_M >> Right_N;

	cout << "CropKeyGen�Լ� ����" << endl;
	string* DecKey = CropKeyGen(M, N,Left_M, Left_N, Right_M, Right_N, Lx_arr, Ly_arr, Rx_arr, Ry_arr);
	cout << "CropKeyGen �Լ� ����" << endl;
	cout << "Decryption �Լ� ����" << endl;
	Dec = Decryption(dst, M, N, DecKey, BlockSize, Left_M, Left_N, Right_M, Right_N);
	cout << "Decryption �Լ� ����" << endl;
	imwrite("Dec_lion_Block16.jpeg", Dec);
#pragma endregion

	return 0;
}


