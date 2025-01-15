## ENVIRONMENT ##

#!/bin/bash

# Error tracking and logging function
log_error() {
    echo "Error: $1" >&2
}

# INSTALL JQ
mkdir -p "$HOME/bin"
curl -L https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 -o "$HOME/bin/jq" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    log_error "Failed to download jq"
    exit 1
fi
chmod +x "$HOME/bin/jq"
sudo ln -sf "$HOME/bin/jq" /usr/local/bin/jq
if [ $? -ne 0 ]; then
    log_error "Failed to set up jq"
    exit 1
fi

# INSTALL PYTHON
sudo apt-get update -q && sudo apt-get install -y python3-pip python3-wheel python3-dev libatlas-base-dev gfortran libopenblas-dev liblapack-dev build-essential  > /dev/null 2>&1
if [ $? -ne 0 ]; then
    log_error "Failed to install Python and pip"
    exit 1
fi

# INSTALL PIP DEPENDENCIES
sudo pip3 install --upgrade pytenable click arrow requests  > /dev/null 2>&1
if [ $? -ne 0 ]; then
    log_error "Failed to install pip dependencies"
    exit 1
fi

# INSTALL OTHER PIP DEPENDENCIES
sudo pip3 install --only-binary=:all: numpy==1.24.4 pandas==2.1.0 boto3==1.28.34 openpyxl==3.1.2  > /dev/null 2>&1
if [ $? -ne 0 ]; then
    log_error "Failed to install pip dependencies"
    exit 1
fi


# SETUP ENVIRONMENT VARIABLES
YEAR=$(date +'%Y')
EVIDENCE_DATE=$(date -d "last sunday +1 day" +'%d %B')
echo "YEAR=$YEAR" >> "$GITHUB_ENV"
echo "EVIDENCE_DATE=$EVIDENCE_DATE" >> "$GITHUB_ENV"
