
man = mkgetopt.1

all: $(man)



mkgetopt.1: mkgetopt-manual.txt
	rst2man.py $< > $@

clean:
	-rm -f mkgetopt.1
