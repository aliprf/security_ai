#!/bin/bash

# ───────────── Color Definitions ─────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

# ───────────── Banner ─────────────
echo -e "${MAGENTA}${BOLD}"
echo "┌────────────────────────────────────────────┐"
echo "│                                            │"
echo "│          🔐  SECURITY AI SETUP             │"
echo "│                                            │"
echo -e "│      ${CYAN}by Aliprf@gmail.com${MAGENTA}        │"
echo "└────────────────────────────────────────────┘"
echo -e "${RESET}"

# ───────────── Step 1: Install Environment ─────────────
echo -e "${CYAN}${BOLD}🔧 Installing Pixi environment...${RESET}"
pixi install

# ───────────── Step 2: Clean Data ─────────────
echo -e "${YELLOW}🧹 Removing old data directory...${RESET}"
rm -rf ./data

# ───────────── Step 3: Setup NVD Data ─────────────

echo -e "${GREEN}${BOLD}📦 Creating .env file and set it up:${RESET}"

#!/bin/bash

ENV_FILE=".env"

if [ ! -f "$ENV_FILE" ]; then
  echo 'env="local"' > "$ENV_FILE"
  echo 'openAIKEY=' >> "$ENV_FILE"
  echo "$ENV_FILE created with default environment variables."
else
  echo "$ENV_FILE already exists."
fi

echo -e "${GREEN}${BOLD}📦 Setting up NVD data for 2025...${RESET}"
mkdir -p ./data/nvd
cd ./data/nvd

echo -e "${YELLOW}🌐 Downloading NVD 2025 CVE feed...${RESET}"
wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2025.json.gz

echo -e "${CYAN}📂 Extracting CVE JSON...${RESET}"
gunzip nvdcve-1.1-2025.json.gz

# ───────────── Step 4: Setup MITRE CTI ─────────────
cd ..
mkdir tmp_cti

echo -e "${GREEN}📥 Cloning MITRE ATT&CK CTI repository...${RESET}"
git clone https://github.com/mitre/cti.git

echo -e "${YELLOW}📁 Moving required files...${RESET}"
mv -f cti/enterprise-attack/relationship ./tmp_cti/relationships
mv -f cti/enterprise-attack/attack-pattern ./tmp_cti/attack-pattern
mv -f cti/enterprise-attack/intrusion-set ./tmp_cti/intrusion-set

echo -e "${RED}🧽 Cleaning up CTI structure...${RESET}"
rm -rf cti
mv -f tmp_cti cti

# ───────────── Done ─────────────
echo -e "${GREEN}${BOLD}✅ Security AI environment setup complete!${RESET}"

