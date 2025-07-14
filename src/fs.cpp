#include "fs.h"
#include "logger.h"
#include <cstring>
#include <cstdlib>
#include <sys/stat.h>

#ifdef _WIN32
    #include <windows.h>
    #include <direct.h>
    #include <io.h>
    #define stat _stat
    #define mkdir(path, mode) _mkdir(path)
    #define access _access
    #define F_OK 0
    #define getcwd _getcwd
    #define chdir _chdir
#else
    #include <unistd.h>
    #include <dirent.h>
    #include <errno.h>
    #include <libgen.h>
#endif

namespace librats {

bool file_exists(const char* path) {
    if (!path) return false;
    
#ifdef _WIN32
    return access(path, F_OK) == 0;
#else
    return access(path, F_OK) == 0;
#endif
}

bool directory_exists(const char* path) {
    if (!path) return false;
    
    struct stat st;
    if (stat(path, &st) == 0) {
        return (st.st_mode & S_IFDIR) != 0;
    }
    return false;
}

bool create_file(const char* path, const char* content) {
    if (!path) return false;
    
    FILE* file = fopen(path, "wb");
    if (!file) {
        LOG_ERROR("FS", "Failed to create file: " << path);
        return false;
    }
    
    if (content) {
        size_t len = strlen(content);
        size_t written = fwrite(content, 1, len, file);
        fclose(file);
        
        if (written != len) {
            LOG_ERROR("FS", "Failed to write complete content to file: " << path);
            return false;
        }
    } else {
        fclose(file);
    }
    
    return true;
}

bool create_file_binary(const char* path, const void* data, size_t size) {
    if (!path) return false;
    
    FILE* file = fopen(path, "wb");
    if (!file) {
        LOG_ERROR("FS", "Failed to create binary file: " << path);
        return false;
    }
    
    if (data && size > 0) {
        size_t written = fwrite(data, 1, size, file);
        fclose(file);
        
        if (written != size) {
            LOG_ERROR("FS", "Failed to write complete binary data to file: " << path);
            return false;
        }
    } else {
        fclose(file);
    }
    
    return true;
}

bool append_to_file(const char* path, const char* content) {
    if (!path || !content) return false;
    
    FILE* file = fopen(path, "ab");
    if (!file) {
        LOG_ERROR("FS", "Failed to open file for appending: " << path);
        return false;
    }
    
    size_t len = strlen(content);
    size_t written = fwrite(content, 1, len, file);
    fclose(file);
    
    if (written != len) {
        LOG_ERROR("FS", "Failed to append complete content to file: " << path);
        return false;
    }
    
    return true;
}

char* read_file_text(const char* path, size_t* size_out) {
    if (!path) return nullptr;
    
    FILE* file = fopen(path, "rb");
    if (!file) {
        LOG_ERROR("FS", "Failed to open file for reading: " << path);
        return nullptr;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size < 0) {
        LOG_ERROR("FS", "Failed to get file size: " << path);
        fclose(file);
        return nullptr;
    }
    
    // Allocate buffer (+1 for null terminator)
    char* buffer = (char*)malloc(file_size + 1);
    if (!buffer) {
        LOG_ERROR("FS", "Failed to allocate memory for file: " << path);
        fclose(file);
        return nullptr;
    }
    
    // Read file
    size_t bytes_read = fread(buffer, 1, file_size, file);
    fclose(file);
    
    // Null terminate
    buffer[bytes_read] = '\0';
    
    if (size_out) {
        *size_out = bytes_read;
    }
    
    return buffer;
}

void* read_file_binary(const char* path, size_t* size_out) {
    if (!path || !size_out) return nullptr;
    
    FILE* file = fopen(path, "rb");
    if (!file) {
        LOG_ERROR("FS", "Failed to open binary file for reading: " << path);
        return nullptr;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size < 0) {
        LOG_ERROR("FS", "Failed to get binary file size: " << path);
        fclose(file);
        return nullptr;
    }
    
    // Allocate buffer
    void* buffer = malloc(file_size);
    if (!buffer) {
        LOG_ERROR("FS", "Failed to allocate memory for binary file: " << path);
        fclose(file);
        return nullptr;
    }
    
    // Read file
    size_t bytes_read = fread(buffer, 1, file_size, file);
    fclose(file);
    
    *size_out = bytes_read;
    return buffer;
}

bool create_directory(const char* path) {
    if (!path) return false;
    
    if (directory_exists(path)) {
        return true; // Already exists
    }
    
#ifdef _WIN32
    return _mkdir(path) == 0;
#else
    return mkdir(path, 0755) == 0;
#endif
}

bool create_directories(const char* path) {
    if (!path) return false;
    
    if (directory_exists(path)) {
        return true; // Already exists
    }
    
    // Create a copy of the path to modify
    size_t len = strlen(path);
    char* path_copy = (char*)malloc(len + 1);
    if (!path_copy) return false;
    
    strcpy(path_copy, path);
    
    // Create parent directories recursively
    for (size_t i = 1; i < len; i++) {
        if (path_copy[i] == '/' || path_copy[i] == '\\') {
            path_copy[i] = '\0';
            
            if (!directory_exists(path_copy)) {
                if (!create_directory(path_copy)) {
                    free(path_copy);
                    return false;
                }
            }
            
            path_copy[i] = '/'; // Normalize to forward slash
        }
    }
    
    // Create the final directory
    bool result = create_directory(path_copy);
    free(path_copy);
    return result;
}

int64_t get_file_size(const char* path) {
    if (!path) return -1;
    
    struct stat st;
    if (stat(path, &st) == 0) {
        return st.st_size;
    }
    return -1;
}

bool is_file(const char* path) {
    if (!path) return false;
    
    struct stat st;
    if (stat(path, &st) == 0) {
        return (st.st_mode & S_IFREG) != 0;
    }
    return false;
}

bool is_directory(const char* path) {
    return directory_exists(path);
}

bool delete_file(const char* path) {
    if (!path) return false;
    
    return remove(path) == 0;
}

bool delete_directory(const char* path) {
    if (!path) return false;
    
#ifdef _WIN32
    return RemoveDirectoryA(path) != 0;
#else
    return rmdir(path) == 0;
#endif
}

bool copy_file(const char* src_path, const char* dest_path) {
    if (!src_path || !dest_path) return false;
    
    size_t size;
    void* data = read_file_binary(src_path, &size);
    if (!data) return false;
    
    bool result = create_file_binary(dest_path, data, size);
    free_file_buffer(data);
    return result;
}

bool move_file(const char* src_path, const char* dest_path) {
    if (!src_path || !dest_path) return false;
    
    if (rename(src_path, dest_path) == 0) {
        return true;
    }
    
    // If rename fails, try copy and delete
    if (copy_file(src_path, dest_path)) {
        return delete_file(src_path);
    }
    
    return false;
}

void free_file_buffer(void* buffer) {
    if (buffer) {
        free(buffer);
    }
}

bool get_current_directory(char* buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return false;
    
    return getcwd(buffer, buffer_size) != nullptr;
}

bool set_current_directory(const char* path) {
    if (!path) return false;
    
    return chdir(path) == 0;
}

} // namespace librats 