/*
 * Critical Vulnerability Test Samples
 * Contains high-severity vulnerabilities that should trigger critical classification
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Critical: Buffer overflow with gets() - extremely dangerous
void critical_buffer_overflow_gets() {
    char buffer[10];
    printf("Enter data: ");
    gets(buffer);  // CWE-120: Critical buffer overflow
    printf("You entered: %s\n", buffer);
}

// Critical: Stack buffer overflow with no bounds checking
void critical_stack_overflow() {
    char small_buffer[8];
    char large_input[1000];
    
    // Fill large input with data
    memset(large_input, 'A', 999);
    large_input[999] = '\0';
    
    strcpy(small_buffer, large_input);  // CWE-121: Critical stack overflow
    printf("Buffer: %s\n", small_buffer);
}

// Critical: Heap buffer overflow
void critical_heap_overflow() {
    char* heap_buffer = (char*)malloc(10);
    if (!heap_buffer) return;
    
    // Intentionally overflow the heap buffer
    strcpy(heap_buffer, "This string is way too long for a 10-byte buffer and will cause heap corruption");  // CWE-122: Critical heap overflow
    
    printf("Heap buffer: %s\n", heap_buffer);
    free(heap_buffer);
}

// Critical: Use after free vulnerability
void critical_use_after_free() {
    char* ptr = (char*)malloc(50);
    if (!ptr) return;
    
    strcpy(ptr, "Important data");
    printf("Data: %s\n", ptr);
    
    free(ptr);  // Free the memory
    
    // Critical: Using freed memory
    strcpy(ptr, "New data");  // CWE-416: Critical use after free
    printf("Data after free: %s\n", ptr);  // Undefined behavior
}

// Critical: Double free vulnerability
void critical_double_free() {
    char* ptr = (char*)malloc(100);
    if (!ptr) return;
    
    strcpy(ptr, "Some data");
    free(ptr);   // First free
    free(ptr);   // CWE-415: Critical double free
}

// Critical: Null pointer dereference
void critical_null_deref(char* input) {
    char* ptr = NULL;
    
    // Conditional allocation that might fail
    if (strlen(input) > 100) {
        ptr = (char*)malloc(200);
    }
    
    // Critical: ptr might still be NULL
    strcpy(ptr, input);  // CWE-476: Critical null pointer dereference
    printf("Result: %s\n", ptr);
    
    if (ptr) free(ptr);
}

// Critical: Format string vulnerability
void critical_format_string(char* user_input) {
    char buffer[100];
    
    // Critical: User input directly in format string
    sprintf(buffer, user_input);  // CWE-134: Critical format string
    printf(buffer);  // Another format string vulnerability
}

// Critical: Integer overflow leading to buffer overflow
void critical_integer_overflow(int size) {
    if (size > 0 && size < 1000000) {
        // Critical: Integer overflow in multiplication
        int total_size = size * 1000000;  // CWE-190: Can overflow
        char* buffer = (char*)malloc(total_size);
        
        if (buffer) {
            // If overflow occurred, this could be a tiny allocation
            memset(buffer, 'A', size * 1000000);  // Buffer overflow
            free(buffer);
        }
    }
}

// Critical: Uncontrolled recursion (stack overflow)
void critical_stack_exhaustion(int depth) {
    char large_array[10000];  // Large stack allocation
    
    if (depth > 0) {
        memset(large_array, depth % 256, sizeof(large_array));
        critical_stack_exhaustion(depth - 1);  // CWE-674: Uncontrolled recursion
    }
}

// Critical: Memory corruption through array bounds
void critical_array_bounds() {
    int array[10];
    int i;
    
    // Critical: Writing beyond array bounds
    for (i = 0; i <= 20; i++) {  // Should be i < 10
        array[i] = i * i;  // CWE-787: Out-of-bounds write
    }
    
    printf("Array[0] = %d\n", array[0]);
}

int main() {
    printf("=== Critical Vulnerability Test Samples ===\n");
    printf("WARNING: This code contains intentional critical vulnerabilities!\n");
    printf("DO NOT compile or run this code!\n");
    printf("This is for static analysis testing only.\n");
    
    // These function calls would trigger the critical vulnerabilities
    // critical_buffer_overflow_gets();
    // critical_stack_overflow();
    // critical_heap_overflow();
    // critical_use_after_free();
    // critical_double_free();
    // critical_null_deref("test input");
    // critical_format_string("%s%s%s%s");
    // critical_integer_overflow(2000);
    // critical_stack_exhaustion(10000);
    // critical_array_bounds();
    
    return 0;
}
