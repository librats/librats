#include <gtest/gtest.h>
#include "fs.h"
#include <iostream>
#include <string>

using namespace librats;

class FSTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Cleanup any leftover test files
        delete_file("test_file.txt");
        delete_file("test_binary.bin");
        delete_file("test_cpp_wrapper.txt");
        delete_directory("test_directory/nested/deep");
        delete_directory("test_directory/nested");
        delete_directory("test_directory");
    }
    
    void TearDown() override {
        // Cleanup test files after each test
        delete_file("test_file.txt");
        delete_file("test_binary.bin");
        delete_file("test_cpp_wrapper.txt");
        delete_directory("test_directory/nested/deep");
        delete_directory("test_directory/nested");
        delete_directory("test_directory");
    }
};

TEST_F(FSTest, BasicFileOperations) {
    const char* test_file = "test_file.txt";
    const char* test_content = "Hello, World!\nThis is a test file.";
    
    // Test file creation
    bool created = create_file(test_file, test_content);
    EXPECT_TRUE(created) << "Failed to create test file";
    std::cout << "✓ File created successfully" << std::endl;
    
    // Test file existence
    bool exists = file_exists(test_file);
    EXPECT_TRUE(exists) << "File should exist after creation";
    std::cout << "✓ File existence check passed" << std::endl;
    
    // Test file reading
    size_t size;
    char* read_content = read_file_text(test_file, &size);
    EXPECT_NE(read_content, nullptr) << "Failed to read file";
    EXPECT_STREQ(read_content, test_content) << "File content mismatch";
    std::cout << "✓ File reading passed" << std::endl;
    std::cout << "  Content: " << read_content << std::endl;
    free_file_buffer(read_content);
    
    // Test file size
    int64_t file_size = get_file_size(test_file);
    EXPECT_EQ(file_size, (int64_t)strlen(test_content)) << "File size mismatch";
    std::cout << "✓ File size check passed (" << file_size << " bytes)" << std::endl;
    
    // Test file type check
    EXPECT_TRUE(is_file(test_file)) << "Should be identified as file";
    EXPECT_FALSE(is_directory(test_file)) << "Should not be identified as directory";
    std::cout << "✓ File type check passed" << std::endl;
    
    // Clean up
    bool deleted = delete_file(test_file);
    EXPECT_TRUE(deleted) << "Failed to delete test file";
    EXPECT_FALSE(file_exists(test_file)) << "File should not exist after deletion";
    std::cout << "✓ File deletion passed" << std::endl;
}

TEST_F(FSTest, DirectoryOperations) {
    const char* test_dir = "test_directory";
    const char* nested_dir = "test_directory/nested/deep";
    
    // Test directory creation
    bool created = create_directory(test_dir);
    EXPECT_TRUE(created) << "Failed to create directory";
    std::cout << "✓ Directory created successfully" << std::endl;
    
    // Test directory existence
    bool exists = directory_exists(test_dir);
    EXPECT_TRUE(exists) << "Directory should exist after creation";
    std::cout << "✓ Directory existence check passed" << std::endl;
    
    // Test nested directory creation
    bool nested_created = create_directories(nested_dir);
    EXPECT_TRUE(nested_created) << "Failed to create nested directories";
    EXPECT_TRUE(directory_exists(nested_dir)) << "Nested directory should exist";
    std::cout << "✓ Nested directory creation passed" << std::endl;
    
    // Test directory type check
    EXPECT_TRUE(is_directory(test_dir)) << "Should be identified as directory";
    EXPECT_FALSE(is_file(test_dir)) << "Should not be identified as file";
    std::cout << "✓ Directory type check passed" << std::endl;
    
    // Clean up (Note: delete_directory only works for empty directories)
    delete_directory(nested_dir);
    delete_directory("test_directory/nested");
    delete_directory(test_dir);
    std::cout << "✓ Directory cleanup completed" << std::endl;
}

TEST_F(FSTest, BinaryFileOperations) {
    const char* binary_file = "test_binary.bin";
    const unsigned char binary_data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0xFE, 0xFD};
    const size_t data_size = sizeof(binary_data);
    
    // Test binary file creation
    bool created = create_file_binary(binary_file, binary_data, data_size);
    EXPECT_TRUE(created) << "Failed to create binary file";
    std::cout << "✓ Binary file created successfully" << std::endl;
    
    // Test binary file reading
    size_t read_size;
    unsigned char* read_data = (unsigned char*)read_file_binary(binary_file, &read_size);
    EXPECT_NE(read_data, nullptr) << "Failed to read binary file";
    EXPECT_EQ(read_size, data_size) << "Binary data size mismatch";
    
    // Compare binary data
    for (size_t i = 0; i < data_size; i++) {
        EXPECT_EQ(read_data[i], binary_data[i]) << "Binary data mismatch at index " << i;
    }
    std::cout << "✓ Binary file reading passed" << std::endl;
    
    free_file_buffer(read_data);
    
    // Clean up
    delete_file(binary_file);
    std::cout << "✓ Binary file cleanup completed" << std::endl;
}

TEST_F(FSTest, CppWrapperFunctions) {
    std::string test_file = "test_cpp_wrapper.txt";
    std::string test_content = "Testing C++ wrapper functions";
    
    // Test C++ string overloads
    bool created = create_file(test_file, test_content);
    EXPECT_TRUE(created) << "Failed to create file using C++ wrapper";
    std::cout << "✓ C++ wrapper file creation passed" << std::endl;
    
    bool exists = file_exists(test_file);
    EXPECT_TRUE(exists) << "File existence check failed with C++ wrapper";
    std::cout << "✓ C++ wrapper existence check passed" << std::endl;
    
    std::string read_content = read_file_text_cpp(test_file);
    EXPECT_EQ(read_content, test_content) << "C++ wrapper content mismatch";
    std::cout << "✓ C++ wrapper file reading passed" << std::endl;
    
    // Clean up
    delete_file(test_file.c_str());
    std::cout << "✓ C++ wrapper cleanup completed" << std::endl;
}

TEST_F(FSTest, FileAppendOperation) {
    const char* test_file = "test_file.txt";
    const char* initial_content = "Initial content";
    const char* append_content = "\nAppended content";
    
    // Create initial file
    EXPECT_TRUE(create_file(test_file, initial_content));
    
    // Append to file
    EXPECT_TRUE(append_to_file(test_file, append_content));
    
    // Read and verify
    std::string expected = std::string(initial_content) + append_content;
    std::string actual = read_file_text_cpp(test_file);
    EXPECT_EQ(actual, expected) << "Appended content mismatch";
    
    std::cout << "✓ File append operation passed" << std::endl;
}

TEST_F(FSTest, FileCopyOperation) {
    const char* src_file = "test_file.txt";
    const char* dest_file = "test_copy.txt";
    const char* test_content = "Content to copy";
    
    // Create source file
    EXPECT_TRUE(create_file(src_file, test_content));
    
    // Copy file
    EXPECT_TRUE(copy_file(src_file, dest_file));
    
    // Verify both files exist and have same content
    EXPECT_TRUE(file_exists(src_file));
    EXPECT_TRUE(file_exists(dest_file));
    
    std::string src_content = read_file_text_cpp(src_file);
    std::string dest_content = read_file_text_cpp(dest_file);
    EXPECT_EQ(src_content, dest_content) << "Copied file content mismatch";
    
    // Clean up
    delete_file(dest_file);
    
    std::cout << "✓ File copy operation passed" << std::endl;
}

TEST_F(FSTest, NonExistentFileOperations) {
    const char* non_existent = "non_existent_file.txt";
    
    // Test operations on non-existent file
    EXPECT_FALSE(file_exists(non_existent));
    EXPECT_FALSE(is_file(non_existent));
    EXPECT_EQ(get_file_size(non_existent), -1);
    EXPECT_EQ(read_file_text(non_existent), nullptr);
    
    size_t size;
    EXPECT_EQ(read_file_binary(non_existent, &size), nullptr);
    
    std::cout << "✓ Non-existent file operations handled correctly" << std::endl;
} 