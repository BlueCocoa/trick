CXX = g++

PREFIX ?= /usr/local
HEADER = trick.hpp
DEMO = trick

demo : $(TARGET)
	$(CXX) -std=c++11 -fPIC main.cpp -o $(DEMO)
    
install :
	install -m 644 $(HEADER) $(PREFIX)/include

uninstall :
	rm -f $(PREFIX)/include/$(HEADER)

clean :
	-rm -f $(DEMO)
