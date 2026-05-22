.PHONY: build build-onefile test install install-onefile uninstall clean

VENV         := .venv
PYINSTALLER  := $(VENV)/bin/pyinstaller
PREFIX       := $(HOME)/.local
BINDIR       := $(PREFIX)/bin
SHAREDIR     := $(PREFIX)/share/idftool

build: $(VENV)
	$(PYINSTALLER) --noconfirm --distpath ./dist-onedir --workpath ./build-onedir idftool-onedir.spec

build-onefile: $(VENV)
	$(PYINSTALLER) --noconfirm --distpath ./dist --workpath ./build idftool.spec

test: build
	./dist-onedir/idftool/idftool --help >/dev/null

install: build
	mkdir -p $(BINDIR)
	rm -rf $(SHAREDIR)
	mkdir -p $(dir $(SHAREDIR))
	cp -R dist-onedir/idftool $(SHAREDIR)
	ln -sf $(SHAREDIR)/idftool $(BINDIR)/idftool

install-onefile: build-onefile
	mkdir -p $(BINDIR)
	cp dist/idftool $(BINDIR)/idftool

uninstall:
	rm -f $(BINDIR)/idftool
	rm -rf $(SHAREDIR)

clean:
	rm -rf build build-onedir dist dist-onedir $(VENV)

$(VENV):
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -e . pyinstaller
