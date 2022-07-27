/***********************************************************************
* 名　称 opensslの一式暗号化ソースコード
* 作　者 written by T.S
* 用　途 強力なパスワードを作成する。
* 動　作 入力された文字列をSHA512でハッシュ後、
*　　　　その値をRSA暗号の公開鍵で暗号化する。
************************************************************************/
#include <stdio.h>
#include <string>
#include <./openssl/engine.h>
#include <./openssl/sha.h>
#include <./openssl/rsa.h>
#include <./openssl/pem.h>
#include <./openssl/applink.c>

#define DEFAULT_MOD_SIZE 1024
#define EXPNT_SIZE 65537

int main() {

	char input[512] = { '\0' }; //入力受付用変数
	unsigned char digest[SHA512_DIGEST_LENGTH] = { '\0' }; //暗号化後変数
	int i = 0; //ループカウンター
	SHA512_CTX sha512; //ハッシュ化したキー値
	unsigned char cryptedhash[512] = { '\0' }; //暗号化されたハッシュ値
	FILE* hashFile; //ハッシュ化したキー値取得用変数
	RSA* rsaKey; //RSA暗号キーペア
	FILE* privateKeyFile; //秘密鍵
	FILE* publicKeyFile; //公開鍵
	FILE* publicExportFile; //公開鍵暗号化ハッシュファイル
	FILE* privateExportFile; //秘密鍵暗号化ハッシュファイル

	//各種ファイル生成
	if ((fopen_s(&hashFile, "hashFile", "w+")) != 0) {
		printf("ハッシュファイルの作成に失敗");
		exit(-1);
	}
	if ((fopen_s(&privateKeyFile, "privateKey.pem", "w")) != 0) {
		printf("秘密鍵ファイルの作成に失敗");
		exit(-1);
	}
	if ((fopen_s(&publicKeyFile, "publicKey.pem", "w")) != 0) {
		printf("公開鍵ファイルの作成に失敗");
		exit(-1);
	}
	if ((fopen_s(&publicExportFile, "publicExportFile", "w")) != 0) {
		printf("公開鍵暗号文ファイルの作成に失敗");
		exit(-1);
	}
	if ((fopen_s(&privateExportFile, "privateExportFile", "w")) != 0) {
		printf("秘密鍵暗号文ファイルの作成に失敗");
		exit(-1);
	}

	//入力受付処理
	printf("512文字以下でパスワードを復号する鍵に設定する文字列を入力して下さい\n鍵対象文字列：");
	fgets(input, sizeof(input), stdin);

	//ハッシュ処理開始
	//SHA512((BYTE*)input,sizeof(input)-1,(BYTE*)hash); //予備のアルゴリズム
	SHA512_Init(&sha512);
	SHA512_Update(&sha512, input, sizeof(input));
	SHA512_Final(digest, &sha512);

	//ハッシュ値ファイル出力
	while (digest[i] != '\0') {
		fprintf_s(hashFile, "%hhu", digest[i]);
		i++;
	}

	//RSA暗号キーペア生成
	rsaKey = RSA_generate_key(DEFAULT_MOD_SIZE * 2, EXPNT_SIZE, NULL, NULL);
	if (rsaKey == NULL) {
		printf("キーの作成に失敗\n");
		exit(-1);
	}

	//PEMフォーマットでプライベートキーファイルを生成
	if (PEM_write_RSAPrivateKey(privateKeyFile, rsaKey, NULL, NULL, 0, NULL, NULL) != 1) {
		printf("秘密鍵の出力に失敗\n");
		exit(-1);
	}

	//PEMフォーマットでパブリックキーファイルを生成
	if (PEM_write_RSA_PUBKEY(publicKeyFile, rsaKey) != 1) {
		printf("公開鍵の出力に失敗\n");
		exit(-1);
	}

	//パブリックキーでハッシュ関数を暗号化
	if (RSA_public_encrypt(strlen((char*)digest),
		(const unsigned char*)digest, cryptedhash, rsaKey, RSA_PKCS1_PADDING) <= 0) {
		printf("パブリックキーで暗号化したハッシュ値の作成に失敗");
		exit(-1);
	}
	while (cryptedhash[i] != '\0') {
		fprintf_s(publicExportFile, "%hhu", cryptedhash[i]);
		i++;
	}

	//プライベートキーでハッシュ関数を暗号化
	if (RSA_private_encrypt(strlen((char*)digest),
		(const unsigned char*)digest, cryptedhash, rsaKey, RSA_PKCS1_PADDING) <= 0) {
		printf("プライベートキーで暗号化したハッシュ値の作成に失敗");
		exit(-1);
	}
	while (cryptedhash[i] != '\0') {
		fprintf_s(privateExportFile, "%hhu", cryptedhash[i]);
		i++;
	}


	//開放処理
	RSA_free(rsaKey);
	fclose(privateKeyFile);
	fclose(publicKeyFile);
	fclose(hashFile);
	fclose(publicExportFile);
	fclose(privateExportFile);

	return 0;
}