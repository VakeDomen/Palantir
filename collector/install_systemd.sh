sudo apt update
sudo apt install -y libpcap-dev

cargo build --release
sudo install -Dm755 target/release/palantir_collector /usr/local/bin/palantir-collector
sudo install -Dm644 palantir-collector.service /etc/systemd/system/palantir-collector.service
sudo systemctl daemon-reload
sudo systemctl enable --now palantir-collector