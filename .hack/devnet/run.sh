#!/bin/bash
__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Get the host IP that containers can reach
HOST_IP="host.docker.internal"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  # On Linux, try to get the docker0 interface IP
  HOST_IP=$(ip -4 addr show docker0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "172.16.0.1")
fi
HOST_IP=$(echo "172.17.0.1")

echo "Host IP for local bootnodoor: $HOST_IP"

# Use custom config if it exists, otherwise use default
if [ -f "${__dir}/custom-kurtosis.devnet.config.yaml" ]; then
  base_config="${__dir}/custom-kurtosis.devnet.config.yaml"
else
  base_config="${__dir}/kurtosis.devnet.config.yaml"
fi

# Create generated config by adding bootnode parameters to base config
cp "$base_config" "${__dir}/generated-kurtosis-config.yaml"

# Ensure 'bootnodoor' is in additional_services and set default bootnodoor_params, preserving user values.
yq_docker() {
  docker run --rm -i -v "${__dir}":"${__dir}" -w "${__dir}" mikefarah/yq "$@"
}

# Add "bootnodoor" to additional_services if it's not present
yq_docker -oy '
  .additional_services |= ((. // []) + ["bootnodoor"] | (sort | unique))
' generated-kurtosis-config.yaml > "${__dir}/generated-kurtosis-config.yaml.tmp" && mv "${__dir}/generated-kurtosis-config.yaml.tmp" "${__dir}/generated-kurtosis-config.yaml"

# Ensure 'bootnodoor_params' exists and set a default image if not set
yq_docker -oy '
  .bootnodoor_params = (.bootnodoor_params // {})
  | .bootnodoor_params.image = (.bootnodoor_params.image // "pk910/dev-images:bootnodoor")
' generated-kurtosis-config.yaml > "${__dir}/generated-kurtosis-config.yaml.tmp" && mv "${__dir}/generated-kurtosis-config.yaml.tmp" "${__dir}/generated-kurtosis-config.yaml"

WITHOUT_SHIM="${WITHOUT_SHIM:-false}"
if [ "$WITHOUT_SHIM" = "false" ]; then
  # Add or update the --devnet-shim argument for bootnodoor_params.extra_args, ensuring only one instance with latest HOST_IP:9000 value exists
  yq_docker -oy '
    .bootnodoor_params = (.bootnodoor_params // {})
    | .bootnodoor_params.extra_args = (
        (
          (.bootnodoor_params.extra_args // [])
          | map(select(test("^--devnet-shim=") | not))
        ) + ["--devnet-shim='"${HOST_IP}"':9000"]
      )
  ' generated-kurtosis-config.yaml > "${__dir}/generated-kurtosis-config.yaml.tmp" && mv "${__dir}/generated-kurtosis-config.yaml.tmp" "${__dir}/generated-kurtosis-config.yaml"
fi

config_file="${__dir}/generated-kurtosis-config.yaml"

## Run devnet using kurtosis
ENCLAVE_NAME="${ENCLAVE_NAME:-bootnodoor}"
ETHEREUM_PACKAGE="${ETHEREUM_PACKAGE:-github.com/ethpandaops/ethereum-package}"
if kurtosis enclave inspect "$ENCLAVE_NAME" > /dev/null; then
  echo "Kurtosis enclave '$ENCLAVE_NAME' is already up."
else
  kurtosis run "$ETHEREUM_PACKAGE" \
  --image-download always \
  --enclave "$ENCLAVE_NAME" \
  --args-file "${config_file}"
fi

ENCLAVE_UUID=$(kurtosis enclave inspect "$ENCLAVE_NAME" --full-uuids | grep 'UUID:' | awk '{print $2}')

# Get el genesis config
kurtosis files inspect "$ENCLAVE_NAME" el_cl_genesis_data "./config.yaml" | tail -n +1 > "${__dir}/generated-cl-config.yaml"

# Get el genesis config
kurtosis files inspect "$ENCLAVE_NAME" el_cl_genesis_data "./genesis.json" | tail -n +1 > "${__dir}/generated-el-genesis.json"

# Get cl genesis validators root
kurtosis files inspect "$ENCLAVE_NAME" el_cl_genesis_data "./genesis_validators_root.txt" | tail -n +1 > "${__dir}/generated-cl-gvr.txt"

# Get el genesis hash
kurtosis files inspect "$ENCLAVE_NAME" el_cl_genesis_data "./deposit_contract_block_hash.txt" | tail -n +1 > "${__dir}/generated-el-hash.txt"

# Get the bootnode container IP and extract private key
echo "Getting bootnode container information..."
BOOTNODE_CONTAINERS=$(kurtosis service ls "$ENCLAVE_NAME" | grep -E "el-bootnode|cl-bootnode" | awk '{print $1}')

BOOTNODOOR_NODE=$(docker ps -aq -f "label=kurtosis_enclave_uuid=$ENCLAVE_UUID" \
              -f "label=kurtosis_service_name=bootnodoor" | tac)

if [ $(echo "$BOOTNODOOR_NODE" | wc -l ) -ne 1 ]; then
  echo "Bootnodoor shim container not found"
  exit 1
fi
BOOTNODOOR_PORT=$(docker inspect --format='{{ (index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort }}' $BOOTNODOOR_NODE)

if [ -z "$BOOTNODOOR_PORT" ]; then
  echo "Bootnodoor api port not found"
  exit 1
fi

echo "Found bootnode at: 127.0.0.1:$BOOTNODOOR_PORT"

# Try to get the private key from the shim API
PRIVATE_KEY=$(curl -s "http://127.0.0.1:${BOOTNODOOR_PORT}/privkey" 2>/dev/null)
if [ -z "$PRIVATE_KEY" ]; then
  echo "Bootnodoor private key not found"
  exit 1
fi

echo "$PRIVATE_KEY" > "${__dir}/generated-bootnodoor-key.txt"
echo "Extracted private key from bootnode"

# Also get ENR and enode for reference
ENR=$(curl -s "http://127.0.0.1:${BOOTNODOOR_PORT}/enr" 2>/dev/null)
ENODE=$(curl -s "http://127.0.0.1:${BOOTNODOOR_PORT}/enode" 2>/dev/null)

cat <<EOF
============================================================================================================
Devnet started successfully!
============================================================================================================
CL Chain config: ${__dir}/generated-cl-config.yaml
EL Genesis config: ${__dir}/generated-el-genesis.json
CL Genesis validators root: ${__dir}/generated-cl-gvr.txt
EL Genesis block hash: ${__dir}/generated-el-hash.txt
Bootnodoor private key: ${__dir}/generated-bootnodoor-key.txt
Database: ${__dir}/generated-database.sqlite
Kurtosis config: ${__dir}/generated-kurtosis-config.yaml

Bootnode Key:   ${PRIVATE_KEY}
Bootnode ENR:   ${ENR}
Bootnode ENODE: ${ENODE}

All devnet nodes are configured to use your local bootnodoor at ${HOST_IP}:9000
============================================================================================================
EOF