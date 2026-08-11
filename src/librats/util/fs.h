#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include "librats/util/rats_export.h"

namespace librats {

// File/Directory existence check
RATS_API bool file_or_directory_exists(const char* path);
RATS_API bool directory_exists(const char* path);
RATS_API bool file_exists(const char* path);

// File creation and writing
RATS_API bool create_file(const char* path, const char* content);
RATS_API bool create_file_binary(const char* path, const void* data, size_t size);
RATS_API bool append_to_file(const char* path, const char* content);

// File reading
RATS_API char* read_file_text(const char* path, size_t* size_out = nullptr);
RATS_API void* read_file_binary(const char* path, size_t* size_out);

// Directory operations
RATS_API bool create_directory(const char* path);
RATS_API bool create_directories(const char* path); // Create parent directories if needed

// File information
RATS_API int64_t get_file_size(const char* path);
RATS_API bool is_file(const char* path);
RATS_API bool is_directory(const char* path);

// File operations
RATS_API bool delete_file(const char* path);
RATS_API bool delete_directory(const char* path);
RATS_API bool copy_file(const char* src_path, const char* dest_path);
RATS_API bool move_file(const char* src_path, const char* dest_path);

// File metadata operations
RATS_API uint64_t get_file_modified_time(const char* path);
RATS_API std::string get_file_extension(const char* path);
RATS_API std::string get_filename_from_path(const char* path);
RATS_API std::string get_parent_directory(const char* path);

// File chunk operations
RATS_API bool write_file_chunk(const char* path, uint64_t offset, const void* data, size_t size);
RATS_API bool read_file_chunk(const char* path, uint64_t offset, void* buffer, size_t size);

// Advanced file operations
RATS_API bool create_file_with_size(const char* path, uint64_t size); // Pre-allocate file space
RATS_API bool rename_file(const char* old_path, const char* new_path);

// A file kept open across many positioned reads/writes. Streaming a large file
// then costs one open()/close() instead of one per chunk (see read_file_chunk /
// write_file_chunk, which re-open every call). 64-bit offsets. NOT thread-safe:
// a stream is meant to be owned by a single thread at a time.
class RATS_API FileStream {
public:
    FileStream() = default;
    ~FileStream() { close(); }
    FileStream(const FileStream&) = delete;
    FileStream& operator=(const FileStream&) = delete;
    FileStream(FileStream&& o) noexcept : f_(o.f_) { o.f_ = nullptr; }
    FileStream& operator=(FileStream&& o) noexcept {
        if (this != &o) { close(); f_ = o.f_; o.f_ = nullptr; }
        return *this;
    }

    bool   open_read(const char* path);   ///< open an existing file for reading
    bool   open_write(const char* path);  ///< open (creating parents+file if needed) for writing
    bool   seek(uint64_t offset);         ///< reposition the cursor
    size_t read(void* buffer, size_t size);                      ///< sequential read; returns bytes read
    bool   write_at(uint64_t offset, const void* data, size_t size);  ///< positioned write
    void   close();
    bool   is_open() const { return f_ != nullptr; }

private:
    FILE* f_ = nullptr;
};

// Directory listing
struct DirectoryEntry {
    std::string name;
    std::string path;
    bool is_directory;
    uint64_t size;
    uint64_t modified_time;
};
RATS_API bool list_directory(const char* path, std::vector<DirectoryEntry>& entries);

// Path utilities
RATS_API std::string combine_paths(const std::string& base, const std::string& relative);
RATS_API bool validate_path(const char* path, bool check_write_access = false);

// Utility functions
RATS_API void free_file_buffer(void* buffer); // Free memory allocated by read functions
RATS_API bool get_current_directory(char* buffer, size_t buffer_size);
RATS_API bool set_current_directory(const char* path);

// C++ convenience wrappers
inline bool file_or_directory_exists(const std::string& path) { return file_or_directory_exists(path.c_str()); }
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

// Additional C++ wrappers for new functions
inline uint64_t get_file_modified_time(const std::string& path) { return get_file_modified_time(path.c_str()); }
inline std::string get_file_extension(const std::string& path) { return get_file_extension(path.c_str()); }
inline std::string get_filename_from_path(const std::string& path) { return get_filename_from_path(path.c_str()); }
inline std::string get_parent_directory(const std::string& path) { return get_parent_directory(path.c_str()); }
inline bool write_file_chunk(const std::string& path, uint64_t offset, const void* data, size_t size) { 
    return write_file_chunk(path.c_str(), offset, data, size); 
}
inline bool read_file_chunk(const std::string& path, uint64_t offset, void* buffer, size_t size) { 
    return read_file_chunk(path.c_str(), offset, buffer, size); 
}
inline bool create_file_with_size(const std::string& path, uint64_t size) { return create_file_with_size(path.c_str(), size); }
inline bool rename_file(const std::string& old_path, const std::string& new_path) { 
    return rename_file(old_path.c_str(), new_path.c_str()); 
}
inline bool validate_path(const std::string& path, bool check_write_access = false) { 
    return validate_path(path.c_str(), check_write_access); 
}

} // namespace librats 