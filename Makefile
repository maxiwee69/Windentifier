CC = cl
CFLAGS = /O1 /MD /EHsc
LDFLAGS = /link /OPT:REF /OPT:ICF
LIBS = Ole32.lib wbemuuid.lib Advapi32.lib Slc.lib
SRC = main.cpp
OUT = windentifier.exe

all: $(OUT)

$(OUT): $(SRC)
    $(CC) $(CFLAGS) $(SRC) $(LIBS) $(LDFLAGS) /OUT:$(OUT)

clean:
    del $(OUT)