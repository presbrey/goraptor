include $(GOROOT)/src/Make.inc

TARG=bitbucket.org/ww/goraptor
CGOFILES=goraptor.go
CGO_OFILES=craptor.o

include $(GOROOT)/src/Make.pkg

format:
	gofmt -w *.go

docs:
	gomake clean
	godoc ${TARG} > README.txt
