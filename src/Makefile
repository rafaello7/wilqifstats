all:: wilqifstats wilqifstats_cgi

wilqifstats: wilqifstats.o
	gcc wilqifstats.o -o wilqifstats -lpcap

wilqifstats_cgi: wilqifstats_cgi.o
	gcc wilqifstats_cgi.o -o wilqifstats_cgi

.c.o:
	gcc -g -c $<

clean:
	rm -f wilqifstats.o wilqifstats wilqifstats_cgi.o wilqifstats_cgi

tar:
	cd ..; tar czf wilqifstats/wilqifstats.tar.gz wilqifstats/Makefile wilqifstats/*.[ch]
