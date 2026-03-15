echo "|-----------------------------------------------------|"
echo "|   YOURE BITCH IS SO LAZY TO DO THIS SHIT YOURSELF   |"
echo "|-----------------------------------------------------|"
# ensure we are in the correct directory if install.sh, generate-config.sh, generate-client-config.sh, diagnose.sh, test-keys-from-keys-file.sh, test-client-keys.sh are in the same directory

LINK_TO_ZIP="https://github.com/AlphaO612/easy_anet/releases/download/v1.0/i-am-so-lazy.zip"

if [ ! -f install.sh ] || [ ! -f generate-config.sh ] || [ ! -f generate-client-config.sh ] || [ ! -f diagnose.sh ] || [ ! -f test-keys-from-keys-file.sh ] || [ ! -f test-client-keys.sh ]; then
    echo "Error: scripts are not in the correct directory"
    echo "Moving to the correct directory..."
    mkdir -p easy_anet
    cd easy_anet
    echo "Downloading scripts..."

    wget $LINK_TO_ZIP -O i-am-so-lazy.zip
    unzip i-am-so-lazy.zip
    rm i-am-so-lazy.zip
fi
chmod +x install.sh generate-config.sh generate-client-config.sh diagnose.sh test-keys-from-keys-file.sh test-client-keys.sh
./install.sh
./generate-config.sh --clients 2
./generate-client-config.sh --server-address $(curl -s https://icanhazip.com):8443
docker compose up -d
./diagnose.sh
./test-keys-from-keys-file.sh
./test-client-keys.sh client-windows/client.toml

echo "Done! "
echo "Your server is running on port 8443/UDP"
echo "--------------------------------"
echo "CONFIG: ./server/server.toml"
echo "CLIENT KEYS: ./server/client-keys.txt"