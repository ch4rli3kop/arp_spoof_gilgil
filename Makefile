CC	= g++
CFLAGS 	= -Wall
TARGET 	= arp_spoof

all : $(TARGET)


$(TARGET) : arp_spoof.o
	$(CC) $(CFLAGS) -o $(TARGET) arp_spoof.cpp -lpcap

clean:
	rm -rf $(TARGET) arp_spoof.o
