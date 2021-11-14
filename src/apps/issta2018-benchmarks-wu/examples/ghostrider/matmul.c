#include <stdio.h> 
#include <assert.h> 
#include <unistd.h>

#define INPUT_SIZE 128

void matmul(int n, int a[][INPUT_SIZE], int b[][INPUT_SIZE], int c[][INPUT_SIZE]) {
    for(int i=0; i<n; ++i)
        for(int j=0; j<n; ++j) {
            c[i][j] = 0;
            for(int k=0; k<n; ++k)
                c[i][j] += a[i][k] * b[k][j];
        }
}
  
int in1[INPUT_SIZE][INPUT_SIZE] = {0}; 
int in2[INPUT_SIZE][INPUT_SIZE] = {0}; 
int out[INPUT_SIZE][INPUT_SIZE] = {0}; 
// Driver program to test above function
int main(int argc, char** argv) 
{ 
    for (int i = 0; i < INPUT_SIZE; i++) {
        for (int j = 0; j < INPUT_SIZE; j++) {
            read(0, &in1[i][j], 1);
            read(0, &in2[i][j], 1);
        }
    }
    matmul(INPUT_SIZE, in1, in2, out); 
    write(1, out, sizeof(out));
    return 0; 
}
