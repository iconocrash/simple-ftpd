ftpsever:
	g++ server.cpp -o ftpserver

.PHONY: clean
 
clean:
	rm -f ftpserver

