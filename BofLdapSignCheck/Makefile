CFLAGS := -Os -s
CXXFLAGS += -w
COMPILED := compiled
CC_x64 := x86_64-w64-mingw32-gcc
STR_x64 := x86_64-w64-mingw32-strip
CC_x86 := i686-w64-mingw32-gcc
STR_x86 := i686-w64-mingw32-strip
RM := rm

ldapsigncheck:
	$(CC_x64) -o $(COMPILED)/ldapsigncheck.x64.o -c ldapsigncheck.c $(CFLAGS) $(CXXFLAGS)
	$(STR_x64) -N ldapsigncheck.c $(COMPILED)/ldapsigncheck.x64.o
	$(CC_x86) -o $(COMPILED)/ldapsigncheck.x86.o -c ldapsigncheck.c $(CFLAGS) $(CXXFLAGS)
	$(STR_x86) -N ldapsigncheck.c $(COMPILED)/ldapsigncheck.x86.o

clean:
	$(RM) $(COMPILED)/*.o