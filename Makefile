CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -march=native
INCLUDES = -Iinclude
LDFLAGS = -static-libgcc -static-libstdc++

SRCDIR = src
INCDIR = include
OBJDIR = build
BINDIR = bin

SOURCES = $(shell find $(SRCDIR) -name "*.cpp")
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)
TARGET = $(BINDIR)/openvpn-manager

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(OBJECTS) | $(BINDIR)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

clean:
	rm -rf $(OBJDIR) $(BINDIR)

install: $(TARGET)
	install -D -m 755 $(TARGET) /usr/local/bin/openvpn-manager
	@echo "installation complete"
	@echo "run 'sudo openvpn-manager' to start"

uninstall:
	rm -f /usr/local/bin/openvpn-manager
	@echo "uninstallation complete"

debug: CXXFLAGS += -g -DDEBUG
debug: $(TARGET)

release: CXXFLAGS += -DNDEBUG
release: $(TARGET)
