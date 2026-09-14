#!/usr/bin/env bash
# Opt-in: creates a dedicated namespace in the current Kubernetes context.
# Never installs node software, credentials, or changes production policies.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
namespace=fqdn-acceptance
if [[ ${FQDN_ACCEPTANCE_CONTEXT:-} != "$(kubectl config current-context)" ]]; then
    echo 'Set FQDN_ACCEPTANCE_CONTEXT to the intended fresh Standard EKS test context.' >&2
    exit 1
fi
if kubectl get namespace "$namespace" >/dev/null 2>&1; then
    echo 'fqdn-acceptance already exists; inspect/remove its prior test evidence before rerunning.' >&2
    exit 1
fi
kubectl apply -f "$repo/test/fqdn/acceptance.yaml"
kubectl -n "$namespace" wait --for=condition=Ready pod --all --timeout=180s
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
kubectl -n "$namespace" exec client -- cat /etc/resolv.conf > "$temporary/resolv.conf"
python3 - "$temporary/resolv.conf" > "$temporary/policies.json" <<'PY'
import ipaddress, json, sys
resolvers = [line.split()[1] for line in open(sys.argv[1]) if line.startswith('nameserver ')]
assert resolvers, 'No configured resolver'
peers = [{'ipBlock': {'cidr': str(ipaddress.ip_network(address))}} for address in resolvers]
metadata = {'name': 'client-isolation', 'namespace': 'fqdn-acceptance'}
network = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy', 'metadata': metadata,
           'spec': {'podSelector': {'matchLabels': {'role': 'fqdn-client'}},
                    'policyTypes': ['Ingress', 'Egress'], 'ingress': [],
                    'egress': [{'to': peers, 'ports': [{'protocol': p, 'port': 53} for p in ['UDP','TCP']]}]}}
anp = {'apiVersion': 'networking.k8s.aws/v1alpha1', 'kind': 'ApplicationNetworkPolicy',
       'metadata': {'name': 'allow-controlled-name', 'namespace': 'fqdn-acceptance'},
       'spec': {'podSelector': {'matchLabels': {'role': 'fqdn-client'}}, 'policyTypes': ['Egress'],
                'egress': [{'to': [{'domainNames': ['allowed.fqdn-acceptance.svc.cluster.local']}],
                            'ports': [{'protocol': 'TCP', 'port': 8080}]}]}}
print(json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': [network, anp]}))
PY
kubectl apply -f "$temporary/policies.json"
allowed_ip=$(kubectl -n "$namespace" get svc allowed -o jsonpath='{.spec.clusterIP}')
denied_ip=$(kubectl -n "$namespace" get svc denied -o jsonpath='{.spec.clusterIP}')

# Pass stdin explicitly to kubectl. Exit failures remain infrastructure or test
# failures; shell output matching never turns exec failures into a deny verdict.
probe() {
    kubectl -n "$namespace" exec -i "$1" -- python3 - "$2" "$3" <<'PY'
import socket, sys
address, expected = sys.argv[1:]
try:
    connection = socket.create_connection((address, 8080), timeout=2)
    connection.sendall(b'GET / HTTP/1.0\r\nHost: fixture\r\n\r\n')
    response = connection.recv(128)
    connection.close()
except (TimeoutError, ConnectionRefusedError, OSError) as error:
    if expected == 'deny':
        print('DENIED', address, repr(error)); sys.exit(0)
    raise
if expected == 'deny':
    sys.exit('FAIL: unexpected access to ' + address)
assert b'200' in response.split(b'\r\n', 1)[0], response
print('ALLOWED', address)
PY
}
probe control "$allowed_ip" allow
probe control "$denied_ip" allow

# Observe enforcement before any allowed-name lookup. This is a convergence
# check, not a claim that independent PolicyEndpoint chunks form a snapshot.
enforced=false
for attempt in $(seq 1 30); do
    if probe client "$denied_ip" deny; then enforced=true; break; fi
    sleep 1
done
[[ $enforced == true ]] || { echo 'Isolation never converged' >&2; exit 1; }
kubectl -n "$namespace" exec client -- python3 -c "import socket; print(socket.getaddrinfo('allowed.fqdn-acceptance.svc.cluster.local',8080))"
probe client "$allowed_ip" allow
probe sibling "$allowed_ip" deny
kubectl -n "$namespace" exec client -- python3 -c "import socket; print(socket.getaddrinfo('denied.fqdn-acceptance.svc.cluster.local',8080))"
probe client "$denied_ip" deny
probe control "$denied_ip" allow
echo 'PASS: reachable allow/deny targets, informational nonmatching DNS, and sibling isolation.'
echo 'Resources retained for inspection. Cleanup: kubectl delete namespace fqdn-acceptance'
