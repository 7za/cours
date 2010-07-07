lib:
	$(CC) -fpic elfreader.c -o libelfreader.so -shared -ldl -Wextra -Wall -W 
	#$(CC) -fpic elfreader.c -o libelfreader.so -shared -ldl -Wextra -Wall -W -ggdb

all: lib
	#$(CC) launcher.c -L. -lelfreader -o launcher -ggdb
	$(CC) launcher.c -L. -lelfreader -o launcher 

clean:
	rm -f *.o *.so test *~
