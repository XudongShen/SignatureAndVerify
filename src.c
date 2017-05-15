#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

FILE _iob[3];

#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

//Here is the key of this program.
//                       PAY ATTENTION!!!!!!!!!!!!!!!!!!
//IF the block is larger than the N in next line, this program wouldn't work!!!!!
//So it doesn't perfect.

#define N "FF807E694D915875B13F47ACDDA61CE11F62E034150F84660BF34026ABAF8C37"
#define E "010001"
#define D "45AEF3CB207EAD939BBDD87C8B0F0CFCC5A366A5AF2AC5FE1261D7547C625F51"

char file[] = "file.pdf";
int fileLength;

void showInfo(char* mem, int pos, int size) {
	for (int i = 0; i < size; i++)
		//printf("%d: %d\t%c\n", i, mem[pos + i], mem[pos + i]);
		printf("%d ", mem[pos + i]);
	printf("\n");
	return;
}

char* getFile(char* fileName) {
	FILE *fp;
	long size;
	char* buf;
	size_t result;

	if ((fp = fopen(fileName, "rb")) == NULL)
		return NULL;
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	rewind(fp);

	buf = (char*)calloc(sizeof(char)*size, sizeof(char));

	result = fread(buf, 1, size, fp);
	if (result != size)
		return NULL;

	fileLength = result;
	fclose(fp);

	return buf;
}

RSA* initRSA() {
	RSA *rsa;

	rsa = RSA_new();
	rsa->flags |= RSA_FLAG_NO_BLINDING;
	rsa->n = BN_new();
	rsa->e = BN_new();
	rsa->d = BN_new();

	BN_hex2bn(&(rsa->n), N);
	BN_hex2bn(&(rsa->e), E);
	BN_hex2bn(&(rsa->d), D);

	return rsa;
}

//This program use RSA_PKCS1_PADDING
//Here sign = 1 for signature
//	   sign = 0 for transport
char* encryptWithCipherStealing(char* plainText, RSA* rsa, int sign) {
	int length, size, i, delta;
	char blockin[21];
	char blockout[32];
	char* cipher;

	if (sign == 1)
		size = 36;
	else
		size = fileLength;
	length = RSA_size(rsa)-11;

	cipher = (char *)calloc(((size/21)+1)*32, sizeof(char));

	for (i = 0; i < size - length; i += length) {
		memcpy(blockin, (void*)(plainText + i), length);
		if (sign == 1)
			RSA_private_encrypt(length, (unsigned char*)blockin, (unsigned char*)blockout, rsa, RSA_PKCS1_PADDING) == -1;
		else
			RSA_public_encrypt(length, (unsigned char*)blockin, (unsigned char*)blockout, rsa, RSA_PKCS1_PADDING) == -1;
		memcpy((void*)(cipher + (i/21)*32), blockout, 32);
	}
	length = size - i;
	memcpy(blockin, (void*)(plainText + i), length);
	if (sign == 1)
		RSA_private_encrypt(length, (unsigned char*)blockin, (unsigned char*)blockout, rsa, RSA_PKCS1_PADDING);
	else
		RSA_public_encrypt(length, (unsigned char*)blockin, (unsigned char*)blockout, rsa, RSA_PKCS1_PADDING);
	memcpy((void*)(cipher + (i / 21) * 32), blockout, 32);
	if (sign == 0)
		fileLength = (fileLength % 21 == 0 ? (fileLength/21*32) : ((fileLength/21)+1)*32);
	return cipher;
}

char* decryptWithCipherStealing(char* cipher, RSA* rsa, int sign) {
	int length, size, i, delta;
	char blockin[32];
	char blockout[21];
	char* plaintext;

	if (sign == 1)
		size = 64;
	else
		size = fileLength;
	length = RSA_size(rsa);

	plaintext = (char *)calloc(size + 1, sizeof(char));

	for (i = 0; i < size - length; i += length) {
		memcpy(blockin, (void*)(cipher + i), length);
		if (sign == 1)
			RSA_public_decrypt(32, (unsigned char*)blockin, (unsigned char*)blockout, rsa, RSA_PKCS1_PADDING);
		else
			RSA_private_decrypt(32, (unsigned char*)blockin, (unsigned char*)blockout, rsa, RSA_PKCS1_PADDING);
		memcpy((void*)(plaintext + (i / 32) * 21), blockout, 21);
	}
	int last;
	memcpy(blockin, (void*)(cipher + i), length);
	if (sign == 1)
		last = RSA_public_decrypt(32, (unsigned char*)blockin, (unsigned char*)blockout, rsa, RSA_PKCS1_PADDING);
	else
		last = RSA_private_decrypt(32, (unsigned char*)blockin, (unsigned char*)blockout, rsa, RSA_PKCS1_PADDING);
	if (last == -1) {
		char * err = malloc(130);;
		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		printf("%s\n", err);
		free(err);
	}
	memcpy((void*)(plaintext + (i / 32) * 21), blockout, last);
	if (sign == 0)
		fileLength = (fileLength / 32-1) * 21 + last;
	return plaintext;
}

//Here get hash value by md5 and sha-1
char* getSign(char* plainText, RSA* rsa) {
	char md5_value[16];
	char sha_value[20];
	char md5_sha_value[36];

	SHA1((unsigned char*)plainText, fileLength, (unsigned char*)sha_value);
	MD5((unsigned char*)plainText, fileLength, (unsigned char*)md5_value);
	memcpy(md5_sha_value, md5_value, 16);
	memcpy((void*)(md5_sha_value + 16), sha_value, 20);
	return encryptWithCipherStealing(md5_sha_value, rsa, 1);
}

int verify(char* plainText, RSA* rsa, char* signature) {
	char md5_value[16];
	char sha_value[20];
	char md5_sha_value[36];

	SHA1((unsigned char*)plainText, fileLength, (unsigned char*)sha_value);
	MD5((unsigned char*)plainText, fileLength, (unsigned char*)md5_value);
	memcpy(md5_sha_value, md5_value, 16);
	memcpy((void*)(md5_sha_value + 16), sha_value, 20);
	return (memcmp(decryptWithCipherStealing(signature, rsa, 1), md5_sha_value, 36) == 0);
}

int outputSignatureFile(char* plainText, char* signature) {
	char* plainTextWithSignature;
	plainTextWithSignature = (char*)calloc(fileLength + 64, sizeof(char));
	memcpy(plainTextWithSignature, plainText, fileLength);
	memcpy((void*)(plainTextWithSignature + fileLength), signature, 64);

	FILE* fp;
	if ((fp = fopen("signature", "wb")) == NULL)
		return 0;

	long size = fwrite(plainTextWithSignature, sizeof(char), fileLength + 64, fp);
	if (size != fileLength + 64)
		return 0;

	fclose(fp);
	return 1;
}

int outputEncryptFile(char* fileName, RSA* rsa) {
	char* plainText = getFile(fileName);
	if (plainText == NULL)
		return 0;

	char* cipher = encryptWithCipherStealing(plainText, rsa, 0);
	FILE* fp;
	if ((fp = fopen("encrypted", "wb")) == NULL)
		return 0;

	long size = fwrite(cipher, sizeof(char), fileLength, fp);
	if (size != fileLength)
		return 0;

	fclose(fp);
	return 1;
}

char* decryptFile(char* fileName, RSA* rsa) {
	char* cipher = getFile(fileName);
	if (cipher == NULL)
		return NULL;

	char* plaintext = decryptWithCipherStealing(cipher, rsa, 0);
	return plaintext;
}

void test() {
	RSA *rsa = initRSA();
	unsigned char plaintext[] =
		"01. A quick brown fox jumps over the lazy dog.\n" \
		"02. A quick brown fox jumps over the lazy dog.\n" \
		"03. A quick brown fox jumps over the lazy dog.\n" \
		"04. A quick brown fox jumps over the lazy dog.\n" \
		"05. A quick brown fox jumps over the lazy dog.\n";
	fileLength = strlen(plaintext);
	char* cipher = encryptWithCipherStealing(plaintext, rsa, 0);
	char* p = decryptWithCipherStealing(cipher, rsa, 0);
	for (int i = 0; i < fileLength; i++)
		printf("%c", p[i]);
}

void check(char* plaintext, RSA* rsa) {
	char block_in[32];
	char block_out[32];
	memcpy(block_in, plaintext, 32);
	RSA_public_encrypt(32, (unsigned char*)block_in, (unsigned char*)block_out, rsa, RSA_NO_PADDING);
	RSA_private_decrypt(32, (unsigned char*)block_out, (unsigned char*)block_in, rsa, RSA_NO_PADDING);
	int i = 1;
	return;
}

int main() {
	_iob[0] = __iob_func()[0];
	_iob[1] = __iob_func()[1];
	_iob[2] = __iob_func()[2];

	//  This is test for encrypt and decrypt
	//	test();

	RSA *rsa = initRSA();

	char* plainText = getFile(file);
	//	check(plainText, rsa);
	//	check(plainText + 20544, rsa);
	//	check(plainText + 27360, rsa);

	if (plainText == NULL) {
		printf("get file failed\n");
		return 0;
	}

	//Calculate the signature
	char* signature = getSign(plainText, rsa);
	if (signature == NULL) {
		printf("get signature failed\n");
		return 0;
	}

	//Attach the signature to the tail of the plaintext
	if (outputSignatureFile(plainText, signature) == 0) {
		printf("create signature file failed\n");
		return 0;
	}

	//Encrypt the signature file
	if (outputEncryptFile("signature", rsa) == 0) {
		printf("create encrypted file failed\n");
		return 0;
	}

	//Decrypt the signature file
	char* plainText_n;
	char signature_n[64] = { 0 };
	char* file_n = decryptFile("encrypted", rsa);
	if (file_n == NULL) {
		printf("decrypt file failed\n");
		return 0;
	}
	fileLength -= 64;
	plainText_n = (char*)calloc(fileLength, sizeof(char));
	memcpy(plainText_n, file_n, fileLength);

	int i;
	for (i = 0; i < fileLength; i++) {
		if (plainText[i] != plainText_n[i])
			printf("%d\n", i);
	}

	memcpy(signature_n, (void*)(file_n + fileLength), 64);

	//Verify the signature
	int result = verify(plainText_n, rsa, signature_n);
	if (result == 1)
		printf("Verify success!\n");
	else
		printf("Verify failed\n");
	return 0;
}