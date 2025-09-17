/*
 * Sample Vulnerable C++ Code for Testing Static Analysis Tools
 * Contains various types of security vulnerabilities for classification testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 1. Buffer Overflow - CWE-120
void buffer_overflow_example() {
    char buffer[10];
    char input[50] = "This string is way too long for the buffer";
    strcpy(buffer, input);  // Vulnerable: no bounds checking
    printf("Buffer: %s\n", buffer);
}

// 2. Format String Vulnerability - CWE-134
void format_string_vuln(char* user_input) {
    printf(user_input);  // Vulnerable: user input directly in format string
}

// 3. Memory Leak - CWE-401
void memory_leak_example() {
    char* ptr = (char*)malloc(100);
    if (ptr == NULL) return;
    
    strcpy(ptr, "Some data");
    printf("Data: %s\n", ptr);
    // Missing free(ptr) - memory leak
}

// 4. Null Pointer Dereference - CWE-476
void null_pointer_deref(char* input) {
    char* ptr = NULL;
    if (strlen(input) > 10) {
        ptr = (char*)malloc(20);
    }
    strcpy(ptr, input);  // Vulnerable: ptr might be NULL
}

// 5. Use After Free - CWE-416
void use_after_free_example() {
    char* ptr = (char*)malloc(50);
    strcpy(ptr, "Hello World");
    free(ptr);
    printf("Data: %s\n", ptr);  // Vulnerable: using freed memory
}

// 6. Integer Overflow - CWE-190
void integer_overflow_example(int size) {
    if (size > 0) {
        int total_size = size * 4;  // Potential overflow
        char* buffer = (char*)malloc(total_size);
        // Use buffer...
        free(buffer);
    }
}

// 7. Uninitialized Variable - CWE-457
void uninitialized_var_example() {
    int value;  // Uninitialized
    if (value > 10) {  // Using uninitialized variable
        printf("Value is greater than 10\n");
    }
}

// 8. Resource Leak - CWE-404
void resource_leak_example() {
    FILE* file = fopen("test.txt", "r");
    if (file != NULL) {
        char buffer[100];
        fgets(buffer, sizeof(buffer), file);
        printf("Read: %s\n", buffer);
        // Missing fclose(file) - resource leak
    }
}

// 9. Race Condition - CWE-362
int global_counter = 0;
void race_condition_example() {
    // Vulnerable: non-atomic increment in multi-threaded environment
    global_counter++;
}

// 10. Command Injection - CWE-78
void command_injection_example(char* filename) {
    char command[256];
    sprintf(command, "cat %s", filename);  // Vulnerable: no input validation
    system(command);
}

// 11. Stack Buffer Overflow - CWE-121
void stack_overflow_example() {
    char small_buffer[8];
    gets(small_buffer);  // Extremely vulnerable function
    printf("Input: %s\n", small_buffer);
}

// 12. Heap Buffer Overflow - CWE-122
void heap_overflow_example() {
    char* heap_buffer = (char*)malloc(10);
    strcpy(heap_buffer, "This string is definitely longer than 10 characters");
    printf("Heap buffer: %s\n", heap_buffer);
    free(heap_buffer);
}

int main() {
    printf("This file contains intentional vulnerabilities for testing purposes.\n");
    printf("DO NOT compile or run this code in production!\n");
    
    // These function calls would trigger the vulnerabilities
    // buffer_overflow_example();
    // format_string_vuln("Hello %s %d");
    // memory_leak_example();
    
    return 0;
}
