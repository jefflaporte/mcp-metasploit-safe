#!/bin/bash

echo "Pulling Metasploit Framework image..."
docker pull metasploitframework/metasploit-framework:latest

echo "Pulling Metasploitable2 image..."
docker pull tleemcjr/metasploitable2:latest

echo "Images pulled successfully"
