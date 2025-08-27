#!/bin/bash

sudo apt update
sudo apt install -y libpcap-dev
sudo apt install -y tshark
sudo systemctl stop palantir-collector
sudo cp target/release/palantir_collector /usr/local/bin/palantir-collector
sudo cp palantir-collector.service /etc/systemd/system/palantir-collector.service
sudo systemctl daemon-reload
sudo systemctl enable --now palantir-collector
sudo systemctl start palantir-collector