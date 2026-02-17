CFLAGS= -Wall -Wextra -O3 -ffast-math -Iinclude
CC=clang
freq_test:
	$(CC) $(CFLAGS) test/freq_test.c src/cipher.c -o freqtest
	./freqtest
	rm freqtest
diff_test:
	$(CC) $(CFLAGS) test/diff_test.c src/cipher.c -o difftest
	./difftest
	rm difftest
mac_test:
	$(CC) $(CFLAGS) test/mac_test.c src/mac.c -o mactest
	./mactest
	rm mactest

