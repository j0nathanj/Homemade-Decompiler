#include <stdio.h>

void fibonacci(int n){
    int result = 0;

    if (n == 1 || n == 2)
    {
        result = 1;
    }
    else
    {
        int curr = 1, prev = 1;
        for (int i = 1; i < n - 1; i++)
        {
            result  = curr + prev;
            prev = curr;
            curr = result;
        }
    }
    
}


int main(int argc, char *argv[], char *envp[]){
    fibonacci(123);
}
