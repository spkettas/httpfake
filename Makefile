#Makefile

CC            = gcc
CXX           = g++
DEFINES       = -D_ENABLE_PCAP
CFLAGS        = -pipe -g -fPIC -Wall -W $(DEFINES)
CXXFLAGS      = -pipe -g -fPIC -Wall -W $(DEFINES)
AR            = ar cqs
LINK          = g++
DEL_FILE      = rm -f
SYMLINK       = ln -f -s
DEL_DIR       = rmdir
MOVE          = mv -f
CHK_DIR_EXISTS= test -d
MKDIR         = mkdir -p

### target
DEPEND_PATH   =
AOTAIN_PATH   = 
PUSH_ROOT	  = ./

LIBS 		  =  -lpcap
						  
INCPATH       = -I. -I./include
SRC_DIR 	  = ./src
OBJECTS_DIR	  = $(PUSH_ROOT)/objs
BIN_DIR 	  = $(PUSH_ROOT)/bin
TARGET 		  = $(BIN_DIR)/httpfake


### code
SOURCES 		= $(wildcard *.c *.cpp)
#OBJS 			= $(patsubst %.c,%.o, $(patsubst %.cpp,%.o, $(SOURCES)))

### more objs
OBJS 			= 	$(OBJECTS_DIR)/main.o \
					$(OBJECTS_DIR)/httpfake.o \
					$(OBJECTS_DIR)/http_parse.o \
					$(OBJECTS_DIR)/packet_sniffer.o
					
					

### Task list
all: app

### Build rules
app: $(TARGET)

$(TARGET): $(OBJECTS_DIR) $(OBJS)
	@$(CHK_DIR_EXISTS) $(BIN_DIR)/ || $(MKDIR) $(BIN_DIR)/
	-$(DEL_FILE) $(TARGET)
	$(LINK) -o $(TARGET) $(OBJS) $(LIBS)

$(OBJECTS_DIR):
		$(CHK_DIR_EXISTS) $@ || mkdir -p $@	

$(OBJECTS_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o "$@" "$<"

	
.PHONY: clean

clean:
	-$(DEL_FILE) $(OBJS)
	-$(DEL_FILE) *~ core *.core

