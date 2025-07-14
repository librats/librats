#pragma once

#include <string>
#include <cstdint>
#include <cstdio>

namespace librats {

// File/Directory existence check
bool file_exists(const char* path);
bool directory_exists(const char* path);

// File creation and writing
bool create_file(const char* path, const char* content);
bool create_file_binary(const char* path, const void* data, size_t size);
bool append_to_file(const char* path, const char* content);

// File reading
char* read_file_text(const char* path, size_t* size_out = nullptr);
void* read_file_binary(const char* path, size_t* size_out);

// Directory operations
bool create_directory(const char* path);
bool create_directories(const char* path); // Create parent directories if needed

// File information
int64_t get_file_size(const char* path);
bool is_file(const char* path);
bool is_directory(const char* path);

// File operations
bool delete_file(const char* path);
bool delete_directory(const char* path);
bool copy_file(const char* src_path, const char* dest_path);
bool move_file(const char* src_path, const char* dest_path);

// Utility functions
void free_file_buffer(void* buffer); // Free memory allocated by read functions
bool get_current_directory(char* buffer, size_t buffer_size);
bool set_current_directory(const char* path);

// C++ convenience wrappers
inline bool file_exists(const std::string& path) { return file_exists(path.c_str()); }
inline bool directory_exists(const std::string& path) { return directory_exists(path.c_str()); }
inline bool create_file(const std::string& path, const std::string& content) { 
    return create_file(path.c_str(), content.c_str()); 
}
inline std::string read_file_text_cpp(const std::string& path) {
    size_t size;
    char* content = read_file_text(path.c_str(), &size);
    if (!content) return "";
    std::string result(content, size);
    free_file_buffer(content);
    return result;
}

} // namespace librats 