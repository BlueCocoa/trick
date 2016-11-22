/*===---- trick.hpp - A library to hook functions and symbols --------------===
 *
 * Copyright © 2016 BlueCocoa. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @(#)trick.hpp 0.1 (BlueCocoa) 2016/11/21
 *
 *===----- Off topic --------------------------------------------------------===
 *
 *  The name 'trick' was token from anime 『桜Trick』
 *  根本停不下来(＊3＊)
 *
 *===------------------------------------------------------------------------===
 */

#ifndef TRICK_HPP
#define TRICK_HPP

#ifdef __APPLE__

#import <dlfcn.h>
#import <libgen.h>
#import <mach/mach.h>
#import <mach/mach_init.h>
#import <mach/vm_map.h>
#import <mach/vm_prot.h>
#import <mach/vm_region.h>
#import <mach/vm_types.h>
#import <mach-o/dyld.h>
#import <mach-o/dyld_images.h>
#import <mach-o/getsect.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <TargetConditionals.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>
#import <syslog.h>
#import <memory>

namespace trick {
// Internal implementations
// "Never enter a detail namespace."
namespace detail {
    // Whether the image was loaded from dyld shared cache
    constexpr static uint32_t kImageFromSharedCacheFlag        = 0x80000000;
    
#if TARGET_OS_OSX
    // 32-bit iOS platform base address
    constexpr static uint32_t k32BitPlatformDefaultBaseAddress = 0x1000;
#else
    // 32-bit macOS platform base address
    constexpr static uint32_t k32BitPlatformDefaultBaseAddress = 0x4000;
#endif
    
    // 64-bit platform base address
    constexpr static uint64_t k64BitPlatformDefaultBaseAddress = 0x100000000;
    
    /**
     *  @brief Get all image headers for given task
     *
     *  @param task Process task_for_pid()
     *  @param image_name Specific image
     *  @param headers (out) image address
     *  @param count   (out) number of images
     *  @param shared_cache_slide (out) Whether a library from the dyld shared cache
     */
    static kern_return_t image_headers_in_task(task_t task, const char * image_name, mach_vm_address_t * headers, uint32_t * count, uint64_t * shared_cache_slide);
    
    /**
     *  @brief Retrive symbol address from given image
     *
     *  @param task Process task_for_pid()
     *  @param remote_header Specific image address
     *  @param symbol_name Symbol name
     *  @param image_from_shared_cache Whether a library from the dyld shared cache
     */
    static mach_vm_address_t scan_remote_image_for_symbol(task_t task, mach_vm_address_t remote_header, const char * symbol_name, bool * image_from_shared_cache);
    
    /**
     *  @brief Copy a string from the target task's address space to current address space.
     *
     *  @param task Process task_for_pid()
     *  @param pointer The address of a string to copyin
     */
    static char * copyin_string(task_t task, mach_vm_address_t pointer);
    
    /**
     *  @brief Try to find symbol addres via given linkedit, text and symtab
     *
     *  @param task Process task_for_pid()
     *  @param remote_header Specific image address
     *  @param symbol_name Symbol name
     *  @param linkedit_addr linkedit address
     *  @param text_addr text address
     *  @param symtab Symbol table information
     */
    template <typename SEGMENT_COMMAND, typename NLIST, typename INT>
    static mach_vm_address_t symbol_address(task_t task, mach_vm_address_t remote_header, const char * symbol_name, mach_vm_address_t linkedit_addr, mach_vm_address_t text_addr, struct symtab_command * symtab) {
        kern_return_t err = KERN_SUCCESS;
        SEGMENT_COMMAND linkedit = {0};
        vm_size_t size = sizeof(SEGMENT_COMMAND);
        err = vm_read_overwrite(task, static_cast<vm_address_t>(linkedit_addr), size, reinterpret_cast<vm_address_t>(&linkedit), &size);
        if (err != KERN_SUCCESS)  {
            syslog(LOG_NOTICE, "[%d] %s failed with error: %s [%d]\n", __LINE__, "vm_read_overwrite()", mach_error_string(err), err);
            return 0;
        }
        
        SEGMENT_COMMAND text = {0};
        err = vm_read_overwrite(task, static_cast<vm_address_t>(text_addr), size, reinterpret_cast<vm_address_t>(&text), &size);
        if (err != KERN_SUCCESS)  {
            syslog(LOG_NOTICE, "[%d] %s failed with error: %s [%d]\n", __LINE__, "vm_read_overwrite()", mach_error_string(err), err);
            return 0;
        }
        
        INT file_slide = linkedit.vmaddr - text.vmaddr - linkedit.fileoff;
        INT strings = static_cast<INT>(remote_header) + symtab->stroff + file_slide;
        INT sym_addr = static_cast<INT>(remote_header) + symtab->symoff + file_slide;
        
        for (uint32_t i = 0; i < symtab->nsyms; i++) {
            NLIST sym = {{0}};
            size = sizeof(NLIST);
            err = vm_read_overwrite(task, static_cast<vm_address_t>(sym_addr), size, reinterpret_cast<vm_address_t>(&sym), &size);
            if (err != KERN_SUCCESS)  {
                syslog(LOG_NOTICE, "[%d] %s failed with error: %s [%d]\n", __LINE__, "vm_read_overwrite()", mach_error_string(err), err);
                return 0;
            }
            
            sym_addr += size;
            
            if (!sym.n_value) continue;
            
            INT symname_addr = strings + sym.n_un.n_strx;
            char *symname = copyin_string(task, symname_addr);
            /* Ignore the leading "_" character in a symbol name */
            if (0 == strcmp(symbol_name, symname + 1)) {
                free(static_cast<void *>(symname));
                /// FIXME: detect thumb mode on 32-bit iOS
                return static_cast<mach_vm_address_t>(sym.n_value);
            }
            free(static_cast<void *>(symname));
        }
        return 0;
    }
    
    static kern_return_t image_headers_in_task(task_t task, const char * image_name, mach_vm_address_t * headers, uint32_t * count, uint64_t * shared_cache_slide) {
        task_flavor_t flavor = TASK_DYLD_INFO;
        task_dyld_info_data_t dyld_info;
        mach_msg_type_number_t number = TASK_DYLD_INFO_COUNT;
        kern_return_t err = KERN_SUCCESS;
        
        err = task_info(task, flavor, reinterpret_cast<task_info_t>(&dyld_info), &number);
        if (err != KERN_SUCCESS) {
            syslog(LOG_NOTICE, "[%d] %s failed with error: %s [%d]\n", __LINE__, "task_info()", mach_error_string(err), err);
            return err;
        }
        
        if (count == nullptr || shared_cache_slide == nullptr) return KERN_FAILURE;
        
        struct dyld_all_image_infos infos;
        vm_size_t size = static_cast<vm_size_t>(dyld_info.all_image_info_size);
        err = vm_read_overwrite(task, static_cast<vm_address_t>(dyld_info.all_image_info_addr), size, reinterpret_cast<vm_address_t>(&infos), &size);
        if (err != KERN_SUCCESS) {
            syslog(LOG_NOTICE, "[%d] %s failed with error: %s [%d]\n", __LINE__, "vm_read_overwrite()", mach_error_string(err), err);
            return err;
        }
        
        *count = infos.infoArrayCount;
        *shared_cache_slide = infos.sharedCacheSlide;
        
        size = sizeof(struct dyld_image_info) * (*count);
        struct dyld_image_info * array = static_cast<struct dyld_image_info *>(malloc(static_cast<size_t>(size)));
        err = vm_read_overwrite(task, reinterpret_cast<vm_address_t>(infos.infoArray), size, reinterpret_cast<vm_address_t>(array), &size);
        if (err != KERN_SUCCESS) {
            syslog(LOG_NOTICE, "[%d] %s failed with error: %s [%d]\n", __LINE__, "vm_read_overwrite()", mach_error_string(err), err);
            free(static_cast<void *>(array));
            return err;
        }
        
        bool should_find_particular_image = (image_name != nullptr);
        if (headers) {
            for (uint32_t i = 0; i < *count; i++) {
                /// FIXME: Find a real location of the first image path
                /* We have to always include the first image in the headers list
                 * because an image filepath's address is slided with an unknown offset,
                 * so we can't read the image name directly. */
                if (!should_find_particular_image || i == 0) {
                    headers[i] = reinterpret_cast<mach_vm_address_t>(array[i].imageLoadAddress);
                } else {
                    char * current_image_name = copyin_string(task, reinterpret_cast<mach_vm_address_t>(array[i].imageFilePath));
                    bool not_found = ({
                        strcmp(image_name, current_image_name) &&
                        strcmp(image_name, basename(current_image_name));
                    });
                    free(static_cast<void *>(current_image_name));
                    
                    if (not_found) {
                        headers[i] = 0;
                    } else {
                        headers[i] = reinterpret_cast<mach_vm_address_t>(array[i].imageLoadAddress);
                        break;
                    }
                }
            }
        }
        
        free(static_cast<void *>(array));
        return KERN_SUCCESS;
    }
    
    static mach_vm_address_t scan_remote_image_for_symbol(task_t task, mach_vm_address_t remote_header, const char * symbol_name, bool * image_from_shared_cache) {
        if (!symbol_name || image_from_shared_cache == nullptr || remote_header == 0) return 0;
        
        kern_return_t err = KERN_FAILURE;
        
        vm_size_t size = sizeof(struct mach_header);
        struct mach_header header = {0};
        err = vm_read_overwrite(task, static_cast<vm_address_t>(remote_header), size, reinterpret_cast<vm_address_t>(&header), &size);
        if (err != KERN_SUCCESS) {
            syslog(LOG_NOTICE, "[%d] %s failed with error: %s [%d]\n", __LINE__, "vm_read_overwrite()", mach_error_string(err), err);
            return 0;
        }
        
        bool sixtyfourbit = (header.magic == MH_MAGIC_64);
        *image_from_shared_cache = ((header.flags & kImageFromSharedCacheFlag) == kImageFromSharedCacheFlag);
        
        if (header.magic != MH_MAGIC && header.magic != MH_MAGIC_64) {
            syslog(LOG_NOTICE, "ERROR: found image with unsupported architecture at %p, skipping it.\n", (void *)remote_header);
            return 0;
        }
        
        mach_vm_address_t symtab_addr = 0;
        mach_vm_address_t linkedit_addr = 0;
        mach_vm_address_t text_addr = 0;
        
        size_t mach_header_size = sizeof(struct mach_header);
        if (sixtyfourbit) {
            mach_header_size = sizeof(struct mach_header_64);
        }
        mach_vm_address_t command_addr = remote_header + mach_header_size;
        struct load_command command = {0};
        size = sizeof(command);
        
        for (uint32_t i = 0; i < header.ncmds; i++) {
            err = vm_read_overwrite(task, static_cast<vm_address_t>(command_addr), size, reinterpret_cast<vm_address_t>(&command), &size);
            if (err != KERN_SUCCESS)  {
                syslog(LOG_NOTICE, "[%d] %s failed with error: %s [%d]\n", __LINE__, "vm_read_overwrite()", mach_error_string(err), err);
                return 0;
            }
            
            if (command.cmd == LC_SYMTAB) {
                symtab_addr = command_addr;
            } else if (command.cmd == LC_SEGMENT || command.cmd == LC_SEGMENT_64) {
                /* struct load_command only has two fields (cmd & cmdsize), while its "child" type
                 * struct segment_command has way more fields including `segname` at index 3, so we just
                 * pretend that we have a real segment_command and skip first two fields away */
                size_t segname_field_offset = sizeof(command);
                mach_vm_address_t segname_addr = command_addr + segname_field_offset;
                char *segname = copyin_string(task, segname_addr);
                if (0 == strcmp(SEG_TEXT, segname)) {
                    text_addr = command_addr;
                } else if (0 == strcmp(SEG_LINKEDIT, segname)) {
                    linkedit_addr = command_addr;
                }
                free(segname);
            }
            // go to next load command
            command_addr += command.cmdsize;
        }
        
        if (!symtab_addr || !linkedit_addr || !text_addr) {
            syslog(LOG_NOTICE, "Invalid Mach-O image header, skipping...\n");
            return 0;
        }
        
        struct symtab_command symtab = {0};
        size = sizeof(struct symtab_command);
        err = vm_read_overwrite(task, static_cast<vm_address_t>(symtab_addr), size, reinterpret_cast<vm_address_t>(&symtab), &size);
        if (err != KERN_SUCCESS)  {
            syslog(LOG_NOTICE, "[%d] %s failed with error: %s [%d]\n", __LINE__, "vm_read_overwrite()", mach_error_string(err), err);
            return 0;
        }
        
        if (sixtyfourbit) {
            return symbol_address<struct segment_command_64, struct nlist_64, uint64_t>(task, remote_header, symbol_name, linkedit_addr, text_addr, &symtab);
        } else {
            return symbol_address<struct segment_command, struct nlist, uint32_t>(task, remote_header, symbol_name, linkedit_addr, text_addr, &symtab);
        }
    }
    
    static char * copyin_string(task_t task, mach_vm_address_t pointer) {
        size_t length = 0;
        
        char buf[2048] = {0};
        char * string = nullptr;
        bool null_terminated = false;
        
        if (pointer) {
            while (!null_terminated) {
                kern_return_t err = KERN_FAILURE;
                vm_size_t sample_size = 2048;
                err = vm_read_overwrite(task, static_cast<vm_address_t>(pointer), sample_size, reinterpret_cast<vm_address_t>(&buf), &sample_size);
                
                char * tmp = static_cast<char *>(realloc(string, length + sample_size));
                if (!tmp) {
                    syslog(LOG_ERR, "[%d] %s failed with error: No enough memory\n", __LINE__, "realloc()");
                    break;
                }
                string = tmp;
                memcpy(static_cast<void *>(string + length), buf, 2048);
                
                size_t max = length + sample_size;
                for (size_t i = length; i < max; i++) {
                    if (string[i] == '\0') {
                        null_terminated = true;
                        break;
                    } else {
                        length++;
                    }
                }
            }
        }
        
        char * result = strdup(string);
        if (string) free(static_cast<void *>(string));
        return result;
    }
}  // detail

/**
 *  @brief Get address of requested symbol
 *
 *  @param symbol_name Symbol name
 *  @param task Process task_for_pid()
 */
mach_vm_address_t get_symbol_address(const char * symbol_name, task_t task = mach_task_self());

/**
 *  @brief Get address of requested symbol in specific image
 *
 *  @param symbol_name Symbol name
 *  @param image_name Specific image
 *  @param task Process task_for_pid()
 */
mach_vm_address_t get_symbol_address_with_image(const char * symbol_name, const char * image_name, task_t task = mach_task_self());

/**
 *  @brief Get a callable function
 */
template <typename FUNCTION>
auto get_function(const char * function_name, task_t task = mach_task_self()) -> FUNCTION {
    // reinterpret the pointer to requested type
    return reinterpret_cast<FUNCTION>(reinterpret_cast<long *>(reinterpret_cast<uint64_t *>(get_symbol_address(function_name, task))));
}

/**
 *  @brief Get a callable function
 */
template <typename FUNCTION>
auto get_function_with_image(const char * function_name, const char * image_name, task_t task = mach_task_self()) -> FUNCTION {
    // reinterpret the pointer to requested type
    return reinterpret_cast<FUNCTION>(reinterpret_cast<long *>(reinterpret_cast<uint64_t *>(get_symbol_address_with_image(function_name, image_name, task))));
}

/**
 *  @brief Get a symbol
 *
 *  @return An lvalue reference to that symbol
 */
template <typename SYMBOL>
auto get_symbol(const char * symbol_name, task_t task = mach_task_self()) -> SYMBOL& {
    // reinterpret the pointer to requested type
    return std::forward<SYMBOL&>(*reinterpret_cast<SYMBOL *>(reinterpret_cast<long *>(reinterpret_cast<uint64_t *>(get_symbol_address(symbol_name, task)))));
}

/**
 *  @brief Get a symbol in specific image
 *
 *  @return An lvalue reference to that symbol
 */
template <typename SYMBOL>
auto get_symbol_with_image(const char * symbol_name, const char * image_name, task_t task = mach_task_self()) -> SYMBOL& {
    // reinterpret the pointer to requested type
    return std::forward<SYMBOL&>(*reinterpret_cast<SYMBOL *>(reinterpret_cast<long *>(reinterpret_cast<uint64_t *>(get_symbol_address_with_image(symbol_name, image_name, task)))));
}

mach_vm_address_t get_symbol_address(const char * symbol_name, task_t task) {
    return get_symbol_address_with_image(symbol_name, nullptr, task);
}

mach_vm_address_t get_symbol_address_with_image(const char * symbol_name, const char * image_name, task_t task) {
    if (!symbol_name || strlen(symbol_name) == 0) return 0;
    
    kern_return_t err = KERN_SUCCESS;
    uint32_t count = 0;
    uint64_t shared_cache_slide = 0;
    
    err = detail::image_headers_in_task(task, image_name, nullptr, &count, &shared_cache_slide);
    if (err != KERN_SUCCESS) {
        return 0;
    }
    
    mach_vm_address_t * headers = static_cast<mach_vm_address_t *>(malloc(sizeof(mach_vm_address_t) * count));
    err = detail::image_headers_in_task(task, image_name, headers, &count, &shared_cache_slide);
    if (err != KERN_SUCCESS) {
        return 0;
    }
    
    mach_vm_address_t result = 0;
    bool image_from_shared_cache = 0;
    
    for (uint32_t i = 0; i < count; i++) {
        mach_vm_address_t image = headers[i];
        result = detail::scan_remote_image_for_symbol(task, image, symbol_name, &image_from_shared_cache);
        if (result > 0) {
            if (i == 0) {
                /* Get a relative symbol offset */
                if (result < detail::k64BitPlatformDefaultBaseAddress)  {
                    result -= detail::k32BitPlatformDefaultBaseAddress;
                } else {
                    result -= detail::k64BitPlatformDefaultBaseAddress;
                }
                /* The header pointer already have ASLR slice included */
                result += headers[0];
            } else if (!image_from_shared_cache) {
                /**
                 * On some setups dyld shared cache doesn't contain some system libraries.
                 * In this case we have to append a base_address+ASLR value to the result.
                 */
                if (headers[i] > detail::k64BitPlatformDefaultBaseAddress && result < detail::k64BitPlatformDefaultBaseAddress) {
                    // 64-bit platform
                    result += headers[i];
                }
                if (headers[i] < detail::k64BitPlatformDefaultBaseAddress && result < detail::k32BitPlatformDefaultBaseAddress) {
                    // 32-bit platform
                    result += headers[i];
                }
            }
            
            break;
        }
    }
    
    free(static_cast<void *>(headers));
    
    // Add a slide if our target image was a library from the dyld shared cache
    if (image_from_shared_cache && result > 0) result += shared_cache_slide;
    
    return result;
}
    
}  // trick

#else
#warning wont work on other platforms
#endif  /* APPLE */

#endif  /* TRICK_HPP */
