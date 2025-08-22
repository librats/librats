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
        delete_file("test_move_src.txt");
        delete_file("test_move_dest.txt");
        delete_file("test_old_name.txt");
        delete_file("test_new_name.txt");
        delete_file("test_metadata.txt");
        delete_file("test_chunks.bin");
        delete_file("test_sized.bin");
        delete_file("validation_test.txt");
        delete_file("test_listing/file1.txt");
        delete_file("test_listing/file2.bin");
        delete_directory("test_listing/subdir");
        delete_directory("test_listing");
        delete_directory("test_change_directory");
        delete_directory("test_directory/nested/deep");
        delete_directory("test_directory/nested");
        delete_directory("test_directory");
    }
    
    void TearDown() override {
        // Cleanup test files after each test
        delete_file("test_file.txt");
        delete_file("test_binary.bin");
        delete_file("test_cpp_wrapper.txt");
        delete_file("test_move_src.txt");
        delete_file("test_move_dest.txt");
        delete_file("test_old_name.txt");
        delete_file("test_new_name.txt");
        delete_file("test_metadata.txt");
        delete_file("test_chunks.bin");
        delete_file("test_sized.bin");
        delete_file("validation_test.txt");
        delete_file("test_listing/file1.txt");
        delete_file("test_listing/file2.bin");
        delete_directory("test_listing/subdir");
        delete_directory("test_listing");
        delete_directory("test_change_directory");
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

TEST_F(FSTest, MoveFileOperation) {
    const char* src_file = "test_move_src.txt";
    const char* dest_file = "test_move_dest.txt";
    const char* test_content = "Content to move";
    
    // Create source file
    EXPECT_TRUE(create_file(src_file, test_content));
    
    // Move file
    EXPECT_TRUE(move_file(src_file, dest_file));
    
    // Verify source doesn't exist and destination exists with correct content
    EXPECT_FALSE(file_exists(src_file));
    EXPECT_TRUE(file_exists(dest_file));
    
    std::string dest_content = read_file_text_cpp(dest_file);
    EXPECT_EQ(dest_content, test_content) << "Moved file content mismatch";
    
    // Clean up
    delete_file(dest_file);
    
    std::cout << "✓ File move operation passed" << std::endl;
}

TEST_F(FSTest, RenameFileOperation) {
    const char* old_name = "test_old_name.txt";
    const char* new_name = "test_new_name.txt";
    const char* test_content = "Content to rename";
    
    // Create file with old name
    EXPECT_TRUE(create_file(old_name, test_content));
    
    // Rename file
    EXPECT_TRUE(rename_file(old_name, new_name));
    
    // Verify old name doesn't exist and new name exists with correct content
    EXPECT_FALSE(file_exists(old_name));
    EXPECT_TRUE(file_exists(new_name));
    
    std::string content = read_file_text_cpp(new_name);
    EXPECT_EQ(content, test_content) << "Renamed file content mismatch";
    
    // Clean up
    delete_file(new_name);
    
    std::cout << "✓ File rename operation passed" << std::endl;
}

TEST_F(FSTest, FileMetadataOperations) {
    const char* test_file = "test_metadata.txt";
    const char* test_content = "Metadata test content";
    
    // Create test file
    EXPECT_TRUE(create_file(test_file, test_content));
    
    // Test file modified time
    uint64_t mod_time = get_file_modified_time(test_file);
    EXPECT_GT(mod_time, 0) << "File modified time should be greater than 0";
    std::cout << "✓ File modified time: " << mod_time << std::endl;
    
    // Test file extension
    std::string ext = get_file_extension(test_file);
    EXPECT_EQ(ext, ".txt") << "File extension should be .txt";
    std::cout << "✓ File extension: " << ext << std::endl;
    
    // Test filename extraction
    std::string filename = get_filename_from_path(test_file);
    EXPECT_EQ(filename, "test_metadata.txt") << "Filename should match";
    std::cout << "✓ Filename from path: " << filename << std::endl;
    
    // Test parent directory
    std::string parent = get_parent_directory("dir/subdir/file.txt");
    EXPECT_EQ(parent, "dir/subdir") << "Parent directory should be correct";
    std::cout << "✓ Parent directory: " << parent << std::endl;
    
    // Clean up
    delete_file(test_file);
    
    std::cout << "✓ File metadata operations passed" << std::endl;
}

TEST_F(FSTest, FileChunkOperations) {
    const char* chunk_file = "test_chunks.bin";
    const char data1[] = "First chunk data";
    const char data2[] = "Second chunk";
    const size_t chunk1_size = strlen(data1);
    const size_t chunk2_size = strlen(data2);
    
    // Write first chunk at offset 0
    EXPECT_TRUE(write_file_chunk(chunk_file, 0, data1, chunk1_size));
    
    // Write second chunk at offset 20
    EXPECT_TRUE(write_file_chunk(chunk_file, 20, data2, chunk2_size));
    
    // Read first chunk
    char buffer1[32] = {0};
    EXPECT_TRUE(read_file_chunk(chunk_file, 0, buffer1, chunk1_size));
    EXPECT_STREQ(buffer1, data1) << "First chunk data mismatch";
    
    // Read second chunk
    char buffer2[32] = {0};
    EXPECT_TRUE(read_file_chunk(chunk_file, 20, buffer2, chunk2_size));
    EXPECT_STREQ(buffer2, data2) << "Second chunk data mismatch";
    
    // Clean up
    delete_file(chunk_file);
    
    std::cout << "✓ File chunk operations passed" << std::endl;
}

TEST_F(FSTest, CreateFileWithSize) {
    const char* sized_file = "test_sized.bin";
    const uint64_t file_size = 1024;
    
    // Create file with specific size
    EXPECT_TRUE(create_file_with_size(sized_file, file_size));
    
    // Verify file exists and has correct size
    EXPECT_TRUE(file_exists(sized_file));
    EXPECT_EQ(get_file_size(sized_file), (int64_t)file_size) << "File size should match";
    
    // Clean up
    delete_file(sized_file);
    
    std::cout << "✓ Create file with size operation passed" << std::endl;
}

TEST_F(FSTest, DirectoryListingOperations) {
    const char* test_dir = "test_listing";
    const char* sub_dir = "test_listing/subdir";
    const char* test_file1 = "test_listing/file1.txt";
    const char* test_file2 = "test_listing/file2.bin";
    
    // Create test directory structure
    EXPECT_TRUE(create_directory(test_dir));
    EXPECT_TRUE(create_directory(sub_dir));
    EXPECT_TRUE(create_file(test_file1, "File 1 content"));
    EXPECT_TRUE(create_file(test_file2, "File 2 content"));
    
    // List directory contents
    std::vector<DirectoryEntry> entries;
    EXPECT_TRUE(list_directory(test_dir, entries));
    
    // Should have 3 entries: subdir, file1.txt, file2.bin
    EXPECT_EQ(entries.size(), 3) << "Should have 3 directory entries";
    
    // Verify entries (order may vary)
    bool found_subdir = false, found_file1 = false, found_file2 = false;
    for (const auto& entry : entries) {
        if (entry.name == "subdir" && entry.is_directory) {
            found_subdir = true;
        } else if (entry.name == "file1.txt" && !entry.is_directory) {
            found_file1 = true;
            EXPECT_GT(entry.size, 0) << "File1 should have size > 0";
        } else if (entry.name == "file2.bin" && !entry.is_directory) {
            found_file2 = true;
            EXPECT_GT(entry.size, 0) << "File2 should have size > 0";
        }
    }
    
    EXPECT_TRUE(found_subdir) << "Should find subdirectory";
    EXPECT_TRUE(found_file1) << "Should find file1.txt";
    EXPECT_TRUE(found_file2) << "Should find file2.bin";
    
    // Clean up
    delete_file(test_file1);
    delete_file(test_file2);
    delete_directory(sub_dir);
    delete_directory(test_dir);
    
    std::cout << "✓ Directory listing operations passed" << std::endl;
}

TEST_F(FSTest, PathUtilities) {
    // Test path combination
    std::string combined1 = combine_paths("base/path", "relative/file.txt");
    EXPECT_EQ(combined1, "base/path/relative/file.txt") << "Path combination failed";
    
    std::string combined2 = combine_paths("base/path/", "/relative/file.txt");
    EXPECT_EQ(combined2, "base/path/relative/file.txt") << "Path combination with separators failed";
    
    std::string combined3 = combine_paths("", "relative/file.txt");
    EXPECT_EQ(combined3, "relative/file.txt") << "Empty base path combination failed";
    
    std::string combined4 = combine_paths("base/path", "");
    EXPECT_EQ(combined4, "base/path") << "Empty relative path combination failed";
    
    // Test path validation
    const char* test_file = "validation_test.txt";
    EXPECT_TRUE(create_file(test_file, "test"));
    
    EXPECT_TRUE(validate_path(test_file, false)) << "Valid existing file should pass validation";
    EXPECT_FALSE(validate_path("non_existent_file.txt", false)) << "Non-existent file should fail validation";
    
    delete_file(test_file);
    
    std::cout << "✓ Path utilities passed" << std::endl;
}

TEST_F(FSTest, DirectoryOperationsAdvanced) {
    char current_dir[1024];
    const char* test_change_dir = "test_change_directory";
    
    // Get current directory
    EXPECT_TRUE(get_current_directory(current_dir, sizeof(current_dir)));
    EXPECT_GT(strlen(current_dir), 0) << "Current directory should not be empty";
    std::cout << "✓ Current directory: " << current_dir << std::endl;
    
    // Create test directory for changing to
    EXPECT_TRUE(create_directory(test_change_dir));
    
    // Change to test directory
    EXPECT_TRUE(set_current_directory(test_change_dir));
    
    // Verify we're in the new directory
    char new_dir[1024];
    EXPECT_TRUE(get_current_directory(new_dir, sizeof(new_dir)));
    std::string new_dir_str(new_dir);
    EXPECT_NE(new_dir_str.find(test_change_dir), std::string::npos) 
        << "Should be in test directory";
    
    // Change back to original directory
    EXPECT_TRUE(set_current_directory(current_dir));
    
    // Clean up
    delete_directory(test_change_dir);
    
    std::cout << "✓ Directory operations advanced passed" << std::endl;
} 