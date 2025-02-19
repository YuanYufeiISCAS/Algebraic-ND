#include <windows.h>
#include <cstdio>
#include <stdio.h>
#include <stdint.h>
#include <cstring>
#include <bcrypt.h>

// "bcrypt.lib" used in Windows for ensuring cryptographic security via a random number generator, while Linux uses the API -- rand().
#pragma comment(lib, "bcrypt.lib")

const int IP_Init_Table[64] =
{
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};

const int E_Table[48] =
{
    32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};

const int P_Table[32] =
{
    16, 7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
     2, 8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};

const int IPR_Table[64] =
{
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
};

const int PC1_Table[56] =
{
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

const int PC2_Table[48] =
{
    14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

const int S_Box[8][4][16] =
{
    //  s1
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    //  s2
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    //  s3
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    //  s4
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    //  s5
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    //  s6
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    //  s7
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    //  s8
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,  
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
};

void uint8ToBitArray(const uint8_t input[], int output[], int numBytes) {
    for (int j = 0; j < numBytes; j++) {
        for (int i = 0; i < 8; i++) {
            output[8 * j + (7 - i)] = (input[j] >> i) & 1;
        }
    }
}

void bitArrayToUint8(const int input[], uint8_t output[], int numBytes) {
    for (int j = 0; j < numBytes; j++) {
        output[j] = 0;
        for (int i = 0; i < 8; i++) {
            output[j] = (output[j] << 1) | input[8 * j + i];
        }
    }
}

void Xor(int *INA, int *INB, int len)
{
    for (int i = 0; i<len; i++)
    {
        *(INA + i) = *(INA + i) ^ *(INB + i);
    }
}

void IP_Init_Rep(const int input[64], int output[64], const int table[64])
{
    for (int i = 0; i < 64; i++)
    {
        output[i] = input[table[i] - 1];
    }
}

void E_Extend(const int input[32], int output[48], const int table[48])
{
    for (int i = 0; i < 48; i++)
    {
        output[i] = input[table[i] - 1];
    }
}

void P_Rep(const int input[32], int output[32], const int table[32])
{
    for (int i = 0; i < 32; i++)
    {
        output[i] = input[table[i] - 1];
    }
}

void IP_Inv_Rep(const int input[64], int output[64], const int table[64])
{
    for (int i = 0; i < 64; i++)
    {
        output[i] = input[table[i] - 1];
    }
}

void PC_1(const int input[64], int output[56], const int table[56])
{
    for (int i = 0; i < 56; i++)
    {
        output[i] = input[table[i] - 1];
    }
}

void PC_2(const int input[56], int output[48], const int table[48])
{
    for (int i = 0; i < 48; i++)
    {
        output[i] = input[table[i] - 1];
    }
}

void S_Comp(const int input[48], int output[32], const int table[8][4][16])
{
    int INT[8];
    for (int i = 0, j = 0; i < 48; i = i + 6)
    {
        INT[j] = table[j][(input[i] << 1)
               + (input[i + 5])][(input[i + 1] << 3)
               + (input[i + 2] << 2)
               + (input[i + 3] << 1)
               + (input[i + 4])];
        j++;
    }
    for (int j = 0; j < 8; j++)
    {
        for (int i = 0; i < 4; i++)
        {
            output[3 * (j + 1) - i + j] = (INT[j] >> i) & 1;
        }
    }
}

void F_func(const int input[32], int output[32], int subKey[48])
{
    int len = 48;
    int temp0[48] = {0};
    int temp1[32] = {0};
    E_Extend(input, temp0, E_Table);
    Xor(temp0, subKey, len);
    S_Comp(temp0, temp1, S_Box);
    P_Rep(temp1, output, P_Table);
}

void RotateL(const int input[28], int output[28], int leftCount)
{
    int len = 28;
    for (int i = 0; i < len; i++)
    {
        output[i] = input[(i + leftCount) % len];
    }
}

void subKey_fun(const int input[64], int subKey[16][48])
{
    int loop0 = 1, loop1 = 2;
    int c[28], d[28];
    int pc_1[56] = {0};
    int pc_2[16][56] = {0};
    int rotatel_c[16][28] = {0};
    int rotatel_d[16][28] = {0};

    PC_1(input, pc_1, PC1_Table);
    for (int i = 0; i < 28; i++)
    {
        c[i] = pc_1[i];
        d[i] = pc_1[i + 28];
    }

    int leftCount = 0;
    for (int i = 1; i < 17; i++)
    {
        if (i == 1 || i == 2 || i == 9 || i == 16)
        {
            leftCount += loop0;
            RotateL(c, rotatel_c[i - 1], leftCount);
            RotateL(d, rotatel_d[i - 1], leftCount);
        }
        else
        {
            leftCount += loop1;
            RotateL(c, rotatel_c[i - 1], leftCount);
            RotateL(d, rotatel_d[i - 1], leftCount);
        }
    }

    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 28; j++)
        {
            pc_2[i][j] = rotatel_c[i][j];
            pc_2[i][j + 28] = rotatel_d[i][j];
        }
    }

    for (int i = 0; i < 16; i++)
    {
        PC_2(pc_2[i], subKey[i], PC2_Table);
    }
}

int encrypt(const uint8_t input[8], const uint8_t inKey[8], const int rounds, uint8_t output[8])
{
    int ip[64] = {0};
    int output_1[64] = {0};
    int subKeys[16][48];
    int chartobit[64] = {0};
    int key[64];
    int l[17][32], r[17][32];

    uint8ToBitArray(input, chartobit, 8);
    // IP_Init_Rep(chartobit, ip, IP_Init_Table);
    uint8ToBitArray(inKey, key, 8);
    subKey_fun(key, subKeys);

    for (int i = 0; i < 32; i++)
    {
        l[0][i] = chartobit[i];
        r[0][i] = chartobit[32 + i];
    }

    for (int j = 1; j < rounds; j++)
    {
        for (int k = 0; k < 32; k++)
        {
            l[j][k] = r[j - 1][k];
        }
        F_func(r[j - 1], r[j], subKeys[j - 1]);
        Xor(r[j], l[j - 1], 32);
    }

    int t = 0;
    for (t = 0; t < 32; t++)
    {
        r[rounds][t] = r[rounds-1][t];
    }
    F_func(r[rounds-1], l[rounds], subKeys[rounds-1]);
    Xor(l[rounds], l[rounds-1], 32);

    for (t = 0; t < 32; t++)
    {
        output_1[t] = l[rounds][t];
        output_1[32 + t] = r[rounds][t];
    }
    // IP_Inv_Rep(output_1, chartobit, IPR_Table);
    bitArrayToUint8(output_1, output, 8);
    // set the label: K_1[22]^K_3[22]
    return subKeys[0][47-22] ^ subKeys[2][47-22];
}

int main(){
	// only for Windows
	NTSTATUS status;
    ULONG cbData = 1000000000;
    UCHAR* randomData = (UCHAR*)malloc(cbData * sizeof(UCHAR));

    if (randomData == NULL) {
        printf("Memory allocate failed\n");
        return -1;
    }

    status = BCryptGenRandom(NULL, randomData, cbData, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    
    if (ERROR_SUCCESS != status) {
        printf("Random numbers generate failed: 0x%x\n", status);
        free(randomData);
        return -1;
    }

	long long idx = 0;
	// only for Windows
	
	FILE *fp = fopen("des_linear_dataset_1.txt", "w");
    if (fp == NULL) {
        perror("Unable to open file!");
        free(randomData);
        return 1;
    }
	
	for(int i = 0; i < 1000000; ++i){
		if(i % 10000 == 0){
			printf("DES Linear Dataset Generation Progress: %.02f\n", i / (1000000.0));
		}
		uint8_t p[8], k[8], c[8], p_mask[8]={0,0,0,0,0,0,0,0}, c_mask[8]={0,0,0,0,0,0,0,0};
		
		// random generate plaintext and key
		for(int j = 0; j < 8; ++j){
			p[j] = randomData[idx++];
			// Set the random number generator for Linux 
			//    --> 
			// srand((unsigned)time(NULL));
			// p[j] = rand() % 256;
		}
		for(int j = 0; j < 8; ++j){
			k[j] = randomData[idx++];
		}
		
		int Y = encrypt(p, k, 3, c);
		
		// get masked data, mask = 7, 18, 24, 29, 47
		uint8_t mask[5] = {31-7, 31-18, 31-24, 31-29, 63-47+32};
		for(int j = 0; j < 5; ++j){
			int index = mask[j] / 8;
			int offset = 7 - (mask[j] % 8);
			p_mask[index] ^= ((p[index] >> offset) & 1) << offset;
			c_mask[index] ^= ((c[index] >> offset) & 1) << offset;
		}
		
		for (int j = 0; j < 8; ++j) {
            fprintf(fp, "%02x", p[j]);
        }
        fprintf(fp, " ");
        for (int j = 0; j < 8; ++j) {
            fprintf(fp, "%02x", p_mask[j]);
        }
        fprintf(fp, " ");
        for (int j = 0; j < 8; ++j) {
            fprintf(fp, "%02x", c[j]);
        }
        fprintf(fp, " ");
        for (int j = 0; j < 8; ++j) {
            fprintf(fp, "%02x", c_mask[j]);
        }
        fprintf(fp, " ");
        fprintf(fp, " %d\n", Y);
	}
	printf("DES Linear Dataset Generate Successful.");
	fclose(fp);
	free(randomData);
	return 0;
}
