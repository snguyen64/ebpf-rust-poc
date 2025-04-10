#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> // For sleep()

int main() {
    printf("Allocating memory...\n");
    void *ptr = malloc(1024); // Allocate 1 KB of memory
    if (ptr == NULL) {
        perror("malloc failed");
        return 1;
    }

    printf("Memory allocated at %p\n", ptr);

    printf("Waiting for 5 seconds...\n");
    sleep(5); // Wait for 5 seconds

    printf("Freeing memory...\n");
    free(ptr); // Free the allocated memory
    printf("Memory freed.\n");

    return 0;
}