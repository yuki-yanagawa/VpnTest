vpnrecv: vpnrecv.o netutil.o
	gcc -o vpnrecv vpnrecv.o netutil.o

netutil.o:
	gcc -c netutil.c

clean:
	rm -f *.o vpnrecv