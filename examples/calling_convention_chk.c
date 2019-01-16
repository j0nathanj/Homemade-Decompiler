#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int global1 = 0xdeadbeef;
char * ptr = NULL;

float int_float(int a, float b){
float c =b;
int d = a;

return d+c;
}

double int_double(int a, double b){
double c = b;
int d = a;

return d+c;
}

float float_int(float a, int b){
float c = a;
int d = b;

return d+c;
}

double double_int(double a, int b){
double c=a;
int d = b;

return d+c;
}

char one_char(char c1){
	char ret = c1+1;
	return ret;
}

char two_chars(char c1, char c2){
	char ret = c1+1;
	ret += c2;
	ret += 1;
	return ret;
}

int four_chars_int(char c1, char c2,char c3, char c4, int a){
	int ret = c1 + c2 + c3 + c4;
	ret += a;
	return ret;
}

int four_chars_two_int(char c1, char c2,char c3, char c4, int a,int b){
	int ret = c1 + c2 + c3 + c4;
	ret += a;
	ret += b;
	return ret;
}

int int_four_chars(int a, char c1, char c2,char c3, char c4){
	int ret = c1 + c2 + c3;
	ret += a;
	return ret;
}

int two_int_four_chars(int a,int b, char c1, char c2,char c3, char c4){
	int ret = c1 + c2 + c3;
	ret += a;
	ret += b;
	return ret;
}

int eight_ints(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8){

return a1+a2+a3+a4+a5+a6+a7+a8;

}

int with_locals(int a, int b){
	int c = 5 * a + b ;
	int d = 7*b +a ;
	return d*c;

}

double double_double(double a, double b){
return a*b + 7;
}


char* return_buffer(char* inp){
	char buf[500];
	strcpy(buf,inp);
	return buf;
}

int mul_by_7(int x){
	int result = x;
	result = result * 5;
	return result;
}

int shift_left(int x, int y){
	return x << y;
}

int loop_test(){
	int i;
	for( i =0; i < 10; i++){
		printf("%d\n", i);
	}
	return i;
}


int loop_if(){
	int i = 0;
	for(i  = 0; i < 10; i++){
		if( i == 5){
			printf("LOL 5\n");
		}
		else{
			printf("NOT 5 :(\n");
		}
		if(i == 3){
			printf("hey 3\n");
		}
		printf("HELLO\n");
	}
	return i;
}


int double_loop(){
	int i = 0;
	int j = 0;
	for(i = 0 ; i < 10; i++){
		for(j = i; j < 20; j++){
			printf("(%d, %d)\n", i, j);
		}
	}
	return i+j;
}

int complex_if(int a, int b){
	if( a > 5 && b < 5)
	{
		a++;
	}

	if(a < 5 || b == 10){
		a++;
	}
	
	return a+b;
}




int main(int argc, char** argv){
	int i = 1;
	float f = 2.2;
	double d = 3.3;
	char c1='a', c2='b', c3='c', c4='d';
	int x = 100;
	int y = 1337;
	int_float(i,f);
	int_double(i,d);
	float_int(f,i);
	double_int(d,i);
	one_char(c1);
	two_chars(c1,c2);
	four_chars_int(c1,c2,c3,c4,i);
	int_four_chars(i,c1,c2,c3,one_char(c4));
	char* check = return_buffer("hello");
	printf("%s\n", check);
	shift_left(x, y); 
	int result = loop_test();
	int result2 = double_loop();
	int result3 = complex_if(5, 6);
	global1 = 0xbad123;
	ptr = malloc(0x40);
	memset(ptr, 0xaa, 0);
	*(ptr) = 'A';
return 1;
}
