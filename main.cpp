/***********************************************************************
* ���@�� openssl�̈ꎮ�Í����\�[�X�R�[�h
* ��@�� written by T.S
* �p�@�r ���͂ȃp�X���[�h���쐬����B
* ���@�� ���͂��ꂽ�������SHA512�Ńn�b�V����A
*�@�@�@�@���̒l��RSA�Í��̌��J���ňÍ�������B
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

	char input[512] = { '\0' }; //���͎�t�p�ϐ�
	unsigned char digest[SHA512_DIGEST_LENGTH] = { '\0' }; //�Í�����ϐ�
	int i = 0; //���[�v�J�E���^�[
	SHA512_CTX sha512; //�n�b�V���������L�[�l
	unsigned char cryptedhash[512] = { '\0' }; //�Í������ꂽ�n�b�V���l
	FILE* hashFile; //�n�b�V���������L�[�l�擾�p�ϐ�
	RSA* rsaKey; //RSA�Í��L�[�y�A
	FILE* privateKeyFile; //�閧��
	FILE* publicKeyFile; //���J��
	FILE* publicExportFile; //���J���Í����n�b�V���t�@�C��
	FILE* privateExportFile; //�閧���Í����n�b�V���t�@�C��

	//�e��t�@�C������
	if ((fopen_s(&hashFile, "hashFile", "w+")) != 0) {
		printf("�n�b�V���t�@�C���̍쐬�Ɏ��s");
		exit(-1);
	}
	if ((fopen_s(&privateKeyFile, "privateKey.pem", "w")) != 0) {
		printf("�閧���t�@�C���̍쐬�Ɏ��s");
		exit(-1);
	}
	if ((fopen_s(&publicKeyFile, "publicKey.pem", "w")) != 0) {
		printf("���J���t�@�C���̍쐬�Ɏ��s");
		exit(-1);
	}
	if ((fopen_s(&publicExportFile, "publicExportFile", "w")) != 0) {
		printf("���J���Í����t�@�C���̍쐬�Ɏ��s");
		exit(-1);
	}
	if ((fopen_s(&privateExportFile, "privateExportFile", "w")) != 0) {
		printf("�閧���Í����t�@�C���̍쐬�Ɏ��s");
		exit(-1);
	}

	//���͎�t����
	printf("512�����ȉ��Ńp�X���[�h�𕜍����錮�ɐݒ肷�镶�������͂��ĉ�����\n���Ώە�����F");
	fgets(input, sizeof(input), stdin);

	//�n�b�V�������J�n
	//SHA512((BYTE*)input,sizeof(input)-1,(BYTE*)hash); //�\���̃A���S���Y��
	SHA512_Init(&sha512);
	SHA512_Update(&sha512, input, sizeof(input));
	SHA512_Final(digest, &sha512);

	//�n�b�V���l�t�@�C���o��
	while (digest[i] != '\0') {
		fprintf_s(hashFile, "%hhu", digest[i]);
		i++;
	}

	//RSA�Í��L�[�y�A����
	rsaKey = RSA_generate_key(DEFAULT_MOD_SIZE * 2, EXPNT_SIZE, NULL, NULL);
	if (rsaKey == NULL) {
		printf("�L�[�̍쐬�Ɏ��s\n");
		exit(-1);
	}

	//PEM�t�H�[�}�b�g�Ńv���C�x�[�g�L�[�t�@�C���𐶐�
	if (PEM_write_RSAPrivateKey(privateKeyFile, rsaKey, NULL, NULL, 0, NULL, NULL) != 1) {
		printf("�閧���̏o�͂Ɏ��s\n");
		exit(-1);
	}

	//PEM�t�H�[�}�b�g�Ńp�u���b�N�L�[�t�@�C���𐶐�
	if (PEM_write_RSA_PUBKEY(publicKeyFile, rsaKey) != 1) {
		printf("���J���̏o�͂Ɏ��s\n");
		exit(-1);
	}

	//�p�u���b�N�L�[�Ńn�b�V���֐����Í���
	if (RSA_public_encrypt(strlen((char*)digest),
		(const unsigned char*)digest, cryptedhash, rsaKey, RSA_PKCS1_PADDING) <= 0) {
		printf("�p�u���b�N�L�[�ňÍ��������n�b�V���l�̍쐬�Ɏ��s");
		exit(-1);
	}
	while (cryptedhash[i] != '\0') {
		fprintf_s(publicExportFile, "%hhu", cryptedhash[i]);
		i++;
	}

	//�v���C�x�[�g�L�[�Ńn�b�V���֐����Í���
	if (RSA_private_encrypt(strlen((char*)digest),
		(const unsigned char*)digest, cryptedhash, rsaKey, RSA_PKCS1_PADDING) <= 0) {
		printf("�v���C�x�[�g�L�[�ňÍ��������n�b�V���l�̍쐬�Ɏ��s");
		exit(-1);
	}
	while (cryptedhash[i] != '\0') {
		fprintf_s(privateExportFile, "%hhu", cryptedhash[i]);
		i++;
	}


	//�J������
	RSA_free(rsaKey);
	fclose(privateKeyFile);
	fclose(publicKeyFile);
	fclose(hashFile);
	fclose(publicExportFile);
	fclose(privateExportFile);

	return 0;
}