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
string* Create_EncKey(int length, string KEY);
string Create_Specific_Location_Key_R(string Msk, int Location, int Length);
string Create_Specific_Location_Key_L(string Msk, int Location);
string* CropKeyGen(int M, int N, int Left_M, int Left_N, int Right_M, int Right_N, string Lx_Msk, string Ly_Msk, string Rx_Msk, string Ry_Msk);
Mat Decryption(Mat EncSrc, int M, int N, string* DecKeyGroup, int BlockSize, int Left_M, int Left_N, int Right_M, int Right_N);
string HexToASCII(string hex);
string EncKey(string lx, string ly, string rx, string ry);

//TODO
// 이미지 사이즈가 BlockSize의 배수가 아니고 약간의 차이가 나는 경우 차이가 나는 부분이 ENC가 되지 않는다.
// 최적화 할 수 있는 부분 상당히 많음


/*
블록 매트릭스 : 사진을 블록사이즈로 나눈 결과로 얻은 매트리스
ex) 48 x 48 사진을 블록사이즈 16으로 나눈 결과를 블록 매트릭스라 할 때,
	이 때, 이 블록 매트릭스의 행의 개수를 M , 열의 개수를 N
*/

#pragma region 키 배열 생성하는 곳

//모든 키를 만들어서 string*로 반환하는 함수
// Decryption함수에서 CropKeyGen함수를 통해서 나온 출력값을 통해서 필요한 DecKey들을 만들어 반환하는 함수
// ex. 사용자의 입력이 0 0 5 6이면 Lx를 기준으로 Lx_key[0]~Lx_Key[N]까지 만들어서 반환함
string* Create_EncKey(int length, string KEY) {
	string *Key = new string[length];
	Key[0] = sha256(KEY);
	for (int i = 1; i < length; i++) Key[i] = sha256(Key[i - 1]);

	return Key;
}
#pragma endregion

#pragma region Dec Key 배열 만들 때 만든 함수
//Lx , Ly와 관련해서 사용자가 Dec하고 싶은 범위 DecKey 생성하는 함수
string Create_Specific_Location_Key_L(string Msk, int Location) {
	string Spec_key = sha256(Msk); // Lx_Key[0] , Ly_Key[0]
	for (int i = 0; i < Location; i++) Spec_key = sha256(Spec_key);

	return Spec_key;
}
//Rx와 관련해서 사용자가 Dec하고 싶은 범위 DecKey 생성하는 함수
string Create_Specific_Location_Key_R(string Msk, int Location, int Length) {
	string Spec_key = sha256(Msk); // Rx_Key[0]
	for (int i = 0; i <Length - Location - 1; i++) 	Spec_key = sha256(Spec_key);

	return Spec_key;
}
#pragma endregion

// Decryption할 범위를 사각형으로 생각했을 때
// 사각형 왼쪽 위 모서리에 있는 블락의 (M,N)을 각각 Left_M , Left_N
// 사각형 오른쪽 위 모서리에 있는 블락의 (M',N')을 각각 Right_M , Right_N
string* CropKeyGen(int M, int N, int Left_M, int Left_N, int Right_M, int Right_N , string Lx_Msk , string Ly_Msk,string Rx_Msk, string Ry_Msk) {
	string* DecKeyGroup = new string[4];
	DecKeyGroup[0] = Create_Specific_Location_Key_L(Lx_Msk, Left_N); //  Lx에 해당
	DecKeyGroup[1] = Create_Specific_Location_Key_L(Ly_Msk, Left_M); // Ly에 해당
	DecKeyGroup[2] = Create_Specific_Location_Key_R(Rx_Msk, Right_N,N); // Rx에 해당
	DecKeyGroup[3] = Create_Specific_Location_Key_R(Ry_Msk, Right_M,M); // Ry에 해당

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
		예시
		M : 10 N : 18
		Left_N : 0 , Left_M : 0
		Right_N : 6 , Right_M : 5
	*/
	Dec_LxKey = Create_EncKey(Right_N-Left_N+1, DecKeyGroup[0]); // Dec_LxKey의 크기 : 18 - 0 = 18
	Dec_LyKey = Create_EncKey(Right_M-Left_M+1, DecKeyGroup[1]); // Dec_LxKey의 크기 : 10 - 0 = 10
	Dec_RxKey = Create_EncKey(Right_N-Left_N+1, DecKeyGroup[2]); // Dec_LxKey의 크기 :  6
	Dec_RyKey = Create_EncKey(Right_M-Left_M+1, DecKeyGroup[3]); // Dec_LxKey의 크기 :  5
	
	for (int i = 0; i < Right_M-Left_M+1; i++) { // i가 0부터 4까지 실행
		for (int j = 0; j < Right_N-Left_N+1; j++) { // j가 0부터 5까지 실행
			int count = 0;
			string EncKeyData = EncKey(Dec_LxKey[j], Dec_LyKey[i], Dec_RxKey[(Right_N-Left_N) - j], Dec_RyKey[(Right_M-Left_M) - i]);
			for (int row = 0; row < BlockSize; row++) {
				for (int col = 0; col < BlockSize; col++) {
					DecSrc.at<uchar>(((BlockSize*(Left_M + i)) + row), ((BlockSize*(Left_N + j)) + col)) ^= EncKeyData[count];
					count++;
				}
			}
			cout << "ENCKEY 파라미터들 LX , LY , RX , RY : " << j << " " << i << " " << (Right_N-Left_N) - j << " " << (Right_M-Left_M) - i << endl;
			cout << "[M,N] ------------  [" << (Left_M + i) << "," << (Left_N + j) << "]" << endl;
		}
	}
	return DecSrc;
}

//Hex string을 ASCII string으로 바꾸는 함수
string HexToASCII(string hex)
{
	int len = hex.length();
	std::string newString;
	for (int i = 0; i< len; i += 2)
	{
		string byte = hex.substr(i, 2);//입력 받은 hex String을 2개씩 쪼개는 곳
		char chr = (char)(int)strtol(byte.c_str(), NULL, 16);// ASCII로 변환하는 곳 
		newString += chr; //newString에 변환하는 값을 저장
	}
	return newString;
}

//블록에 맞는 lx , ly , rx , ry 키를 입력으로 갖고, sha256을 8번 돌려서 append 한 것을 반환하는 함수
string EncKey(string lx, string ly, string rx, string ry) {
	std::string tempKey = sha256(lx + ly + rx + ry);
	for (int i = 0; i < 7; i++)	
		tempKey += sha256(tempKey);
	//sha256함수를 돌려서 나온 결과물이 hex string이어서 HexToASCII함수를 만듬
	string EncKey = HexToASCII(tempKey); 

	return EncKey;
}

// 입력값 : Encryption할 사진 , Lx 키배열 , Rx 키배열 , Ly 키배열 , Ry 키배열 , 블록 매트릭스의 행의 개수 , 블록 매트릭스의 열의 개수
Mat Encryption_Matrix(Mat src,string* LxKey,string* RxKey,string* LyKey,string* RyKey,int M,int N,int BlockSize) {
	Mat EncMat = src.clone(); // Encryption된 사진을 넣을 행렬
	
		for (int m = 0; m < M; m++) { // 블록매트릭스의 행만큼 실행되는 함수
			for (int n = 0; n < N; n++) { //블록매트릭스의 열만큼 실행되는 함수 지금까지 M*N번
				string BlockData = ""; // 하나의 블록에 대한 데이터를 저장할 임시 string 변수
				for (int i = 0; i < BlockSize; i++) {
					for (int j = 0; j < BlockSize; j++) 
						BlockData += src.at<uchar>((BlockSize * m) + i, (BlockSize * n) + j);//블록에 대한 데이터를 BlockData에 저장				
				}
				
				string EncKeyData = EncKey(LxKey[n], LyKey[m], RxKey[N - n-1], RyKey[M - m-1]);//블록에 맞는 Encryption 키 생성하여 저장
				int count = 0;
				for (int block_row = 0; block_row < BlockSize; block_row++) {
					for (int block_col = 0; block_col < BlockSize; block_col++) {
						EncMat.at<uchar>((BlockSize * m) + block_row, (BlockSize * n) + block_col) = BlockData[count] ^ EncKeyData[count];// XOR하는 부분
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
	M = src.rows / BlockSize; // 블록 매트릭스의 행의 개수
	N = src.cols / BlockSize; // 블록 매트릭스의 열의 개수
	cout << "블록 매트릭스의 행 - M : " << M << endl << "블록 매트릭스의 열 - N : "<< N << endl<<endl;
	cout << " src의 행 - M' : " << src.rows << endl << " src의 열 - N' : " << src.cols << endl << endl;
	if (!src.data)
	{
		return -1;
	}	
	// LX, LY, RX , RY에 맞는 키 배열을 생성하는 곳
	cout << "LX, LY, RX , RY에 맞는 키 배열을 생성하는 곳" << endl;
	string* Lx_key = Create_EncKey(N,Lx_arr);
	string* Ly_key = Create_EncKey(M,Ly_arr);
	string* Rx_key = Create_EncKey(N,Rx_arr);
	string* Ry_key = Create_EncKey(M,Ry_arr);
	cout << "키 배열 생성 종료" << endl;

	cout << "Lx_Key 처음 : " <<Lx_key[1] << endl;
	cout << "Ly_Key 처음 : " << Ly_key[1] << endl;
	cout << "Rx_Key 처음 : " << Rx_key[N-2-1] << endl;
	cout << "Ry_Key 처음 : " << Ry_key[M-2-1] << endl;
	
#pragma region Encryption 부분
	cout << "Encryption 시작" << endl<<endl;
	dst = Encryption_Matrix(src, Lx_key, Rx_key, Ly_key, Ry_key,M,N,BlockSize);
	imwrite("Enc_lion_Block16.jpeg", dst);
	cout << "Encryption 종료" << endl<<endl;
#pragma endregion

#pragma region Decryption 부분
	cout << "Decryption" << endl << "Decryption 할 범위"<<endl<<"왼쪽 맨 위 블락의 행(M)과 열(N)\n오른쪽 맨 밑 블락의 행(M')과 열(N')\n입력 예시(ex. 0 0 5 6 , M'>M and N'>N)" << endl;

	cin >> Left_M >> Left_N >> Right_M >> Right_N;

	cout << "CropKeyGen함수 실행" << endl;
	string* DecKey = CropKeyGen(M, N,Left_M, Left_N, Right_M, Right_N, Lx_arr, Ly_arr, Rx_arr, Ry_arr);
	cout << "CropKeyGen 함수 종료" << endl;
	cout << "Decryption 함수 실행" << endl;
	Dec = Decryption(dst, M, N, DecKey, BlockSize, Left_M, Left_N, Right_M, Right_N);
	cout << "Decryption 함수 종료" << endl;
	imwrite("Dec_lion_Block16.jpeg", Dec);
#pragma endregion

	return 0;
}


