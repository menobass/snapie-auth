#!/usr/bin/env bash
# Generate RS256 JWT keypair for snapie-auth.
# Run once on first deploy: bash scripts/gen-keys.sh

set -e
mkdir -p keys

if [ -f keys/jwt-private.pem ]; then
  echo "keys/jwt-private.pem already exists — delete it first if you want to regenerate."
  exit 1
fi

openssl genpkey -algorithm RSA -out keys/jwt-private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in keys/jwt-private.pem -out keys/jwt-public.pem

echo "Generated keys/jwt-private.pem and keys/jwt-public.pem"
echo "Update JWT_KEY_ID in .env to a new unique value (e.g. snapie-auth-$(date +%Y-%m))."
