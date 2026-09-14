# VPC CNI packaging prerequisite

Base: `aws/amazon-vpc-cni-k8s` commit `c038e4258f01dbe63104d3f2935063877dd8a31d`.

Apply `0001-fqdn-nodeagent-feature-gate.patch` with `git apply --check`, then `git apply` in that checkout. The patch adds `nodeAgent.fqdn` to the existing VPC CNI Helm chart. It changes the arguments of the existing `aws-eks-nodeagent` container; no additional workload or CNI component is installed.

The default remains disabled and adds no new arguments to the old image. When enabled, set `nodeAgent.enabled=true` and `enableNetworkPolicy=true`, select the built agent through `nodeAgent.image.override` (the exact image reference) or `nodeAgent.image.overrideRepository` plus its built tag, and provide every resource and timeout setting from qualification measurements. Helm rejects missing, zero, negative or noninteger budgets and empty timeouts. It also rejects enablement with the unmodified default image or a disabled nodeagent. The binary independently validates timeouts, memory reservations and kernel hard caps.

Validated with Helm 3.18.6: strict lint and enabled rendering pass with explicit synthetic test values; disabled rendered manifests match the pinned baseline. Pod, PE and CPE `get/list/watch` permissions already exist in the chart. These render checks do not establish production resource budgets.

The chart cannot upgrade the EKS managed controller or AWS's add-on schema. Those release dependencies must be qualified separately. This patch is an independently applicable integration change, not a claim that AWS's managed add-on accepts these values today.

Use a dedicated canary node group with appropriate scheduling restrictions. Changing the single cluster-wide `aws-node` DaemonSet value alone is not a per-node rollout strategy. Rollback requires draining/replacing selected nodes or installing equivalent enforcement before disabling interception. In-place removal of FQDN enforcement from running dependent workloads is unsafe.
