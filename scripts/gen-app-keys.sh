#!/usr/bin/env bash
# Generate the RS256 keypair used to sign "Sign in with Snapie" app tokens.
# Separate from the session keys (scripts/gen-keys.sh): tokens handed to third parties must never
# be usable as a Snapie session. Safe to run on an existing deployment; touches no other key.
# The public half is served at /.well-known/jwks.json.

set -e
mkdir -p keys

if [ -f keys/app-private.pem ]; then
  echo "keys/app-private.pem already exists — delete it first if you want to regenerate."
  exit 1
fi

openssl genpkey -algorithm RSA -out keys/app-private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in keys/app-private.pem -out keys/app-public.pem
chmod 600 keys/app-private.pem

echo "Generated keys/app-private.pem and keys/app-public.pem"
echo "Set APP_JWT_KEY_ID in .env (e.g. snapie-app-$(date +%Y-%m)) and restart."
