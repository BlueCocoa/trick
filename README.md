# trick
A library to hook functions and symbols

Tested on macOS in 32/64 bit environment

Tested on iOS in 64 bit environment

### Installation
```$ sudo make install```

### Usage

	#import <iostream>
	#import <string>
	#import "trick.hpp"

	using namespace std;
	using namespace trick;

	#pragma mark Hook function

	__attribute__((visibility("hidden")))
	void cpp_func(std::string via) {
		printf("cpp_func called %s\n", via.c_str());
	}

	static void (*orig_func)(std::string via);
	void my_func(std::string via) {
		orig_func(via);
	}

	#pragma mark Hook global ariables

	class foo {
	public:
		int data;
	};

	static foo glob_foo;
	static std::string glob_var;

	int main(int argc, const char * argv[]) {
		glob_foo.data = 233;
		glob_var = "Hello";
		
		// Please note that the symbol name possibly *VARIES* when use different compilers and settings
		// In this example,
		/*
		 
		 Apple LLVM version 8.0.0 (clang-800.0.42.1)
		 Target: x86_64-apple-darwin16.1.0
		 Thread model: posix
		 Xcode version: Version 8.1 (8B62)
		 
		 */
		
	#pragma mark symbol
		
		mach_vm_address_t addr = trick::get_symbol_address("_ZL8glob_var");
		printf("_ZL8glob_var: %p\n", (void *)addr);
		
		trick::get_symbol<std::string>("_ZL8glob_var") += " World!";
		printf("glob_var: %s\n", glob_var.c_str());
		
		addr = trick::get_symbol_address("_ZL8glob_foo");
		printf("_ZL8glob_foo: %p\n", (void *)addr);
		
		trick::get_symbol<class foo>("_ZL8glob_foo").data = 2333;
		printf("glob_foo.data: %d\n", glob_foo.data);
		
	#pragma mark function
		
		cpp_func("directly");
		
		addr = trick::get_symbol_address("_Z8cpp_funcNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE");
		printf("void cpp_func(std::string): %p\n", (void *)addr);
		
		trick::get_function<void(*)(std::string)>("_Z8cpp_funcNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE")("via trick::get_function");
		return 0;
	}


### Screenshots

![Screenshots](https://raw.githubusercontent.com/BlueCocoa/trick/master/screenshot.png)

### 『桜Trick』

![『桜Trick』](https://raw.githubusercontent.com/BlueCocoa/trick/master/SakuraTrick.jpg)
