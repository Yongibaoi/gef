#!/bin/sh -eux

if [ ! $(id -u) = 0 ]; then
  echo "[-] Detected non-root user, install failed."
  exit 1
fi

echo "[+] apt"
apt-get update
apt-get install -y gdb-multiarch binutils gcc file python3-pip ruby-dev git

echo "[+] pip3"
pip3 install crccheck unicorn capstone ropper keystone-engine

echo "[+] install seccomp-tools, one_gadget"
if [ "x$(which seccomp-tools)" = "x" ]; then
  gem install seccomp-tools
fi

if [ "x$(which one_gadget)" = "x" ]; then
  gem install one_gadget
fi

echo "[+] install rp++"
if [ "x$(uname -m)" = "xx86_64" ]; then
  if [ "x$(which rp-lin)" = "x" ]; then
    wget -q https://github.com/0vercl0k/rp/releases/download/v2.1.1/rp-lin-clang.zip -P /tmp
    unzip /tmp/rp-lin-clang.zip -d /usr/local/bin/
    chmod +x /usr/local/bin/rp-lin
    rm /tmp/rp-lin-clang.zip
  fi
fi

echo "[+] install vmlinux-to-elf"
if [ "x$(which vmlinux-to-elf)" = "x" ]; then
  pip3 install --upgrade lz4 zstandard git+https://github.com/clubby789/python-lzo@b4e39df
  pip3 install --upgrade git+https://github.com/marin-m/vmlinux-to-elf
fi

echo "[+] download gef"
wget -q https://raw.githubusercontent.com/bata24/gef/dev/gef.py -O /root/.gdbinit-gef.py

echo "[+] setup gef"
STARTUP_COMMAND="source /root/.gdbinit-gef.py"
if [ ! -e /root/.gdbinit ] || [ "x$(grep "$STARTUP_COMMAND" /root/.gdbinit)" = "x" ]; then
  echo "$STARTUP_COMMAND" >> /root/.gdbinit
fi

exit 0
