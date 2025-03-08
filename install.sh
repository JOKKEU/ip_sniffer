#!/bin/bash

DIR_NAME="build"
PROG_NAME="sniffer"
BUFFERING_FLAG=""

# Проверка наличия аргументов
if [ "$1" == "--no-buffering" ]; then
    BUFFERING_FLAG=""
elif [ "$1" == "--buffering" ]; then
    BUFFERING_FLAG="-D BUFFERING=1"
else
    echo "Использование: $0 [--buffering | --no-buffering]"
    exit 1
fi

if [ -d "$DIR_NAME" ]; then 
    echo "[+] dir exists, clearing dir"
    rm -rf "$DIR_NAME"
fi

mkdir "$DIR_NAME"
echo "[+] directory created"

cd "$DIR_NAME" || exit
echo "[+] moved to -> $DIR_NAME"

if command -v gcc > /dev/null 2>&1; then
    echo "[+] gcc found"
    gcc $BUFFERING_FLAG -Wno-incompatible-pointer-types -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast -Wno-implicit-function-declaration ../main.c ../ip_sniffer.c -o $PROG_NAME
    if [ $? -eq 0 ]; then 
        echo "[+] program compiled"
    else 
        echo "[-] compilation error"
        exit 1
    fi
else
    echo "[-] gcc not found, checking your OS"
    os_name=$(grep '^ID=' /etc/os-release | cut -d '=' -f2 | tr -d '"')
    
    if [[ "${os_name,,}" == "fedora" ]] || [[ "${os_name,,}" == "centos" ]]; then
        echo "[+] installing gcc"
        sudo dnf install g++ -y  
    elif [[ "${os_name,,}" == "ubuntu" ]] || [[ "${os_name,,}" == "kali" ]]; then
        echo "[+] installing g++"
        sudo apt install g++ -y
    elif [[ "${os_name,,}" == "arch" ]]; then
        echo "[+] installing gcc"
        sudo pacman -S g++ --noconfirm 
    else
        echo "Could not determine your OS"
        exit 1
    fi
    
    echo "[+] finished installing gcc"
    gcc $BUFFERING_FLAG -Wno-incompatible-pointer-types -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast -Wno-implicit-function-declaration ../main.c ../ip_sniffer.c -o $PROG_NAME
    if [ $? -eq 0 ]; then 
        echo "[+] program compiled"
    else 
        echo "[-] compilation error"
        exit 1
    fi
fi

sudo cp $PROG_NAME /usr/local/bin
echo "[+] program copied to /usr/local/bin"
echo "===== PROG INSTALLED ====="
echo "[+] run program (global scope) -> $PROG_NAME"
echo "[+] Usage: $PROG_NAME --help"
cd .. || exit
