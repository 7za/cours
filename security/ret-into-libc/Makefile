

all: clean vulni loader

indent:
	indent -linux *.c *.h
	rm -f *~

vulni:
	gcc vulni.c -o vulni -ggdb

loader:
	gcc loader.c -o loader -ggdb 

clean:
	rm -f loader vulni core *~

