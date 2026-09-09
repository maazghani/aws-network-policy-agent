# VPC CNI packaging prerequisite

Base: `aws/amazon-vpc-cni-k8s` commit `c038e4258f01dbe63104d3f2935063877dd8a31d`.

Apply `0001-fqdn-nodeagent-feature-gate.patch` with `git apply --check`, then `git apply` in that checkout. The patch adds `nodeAgent.fqdn` to the existing VPC CNI Helm chart. It changes the arguments of the existing `aws-eks-nodeagent` container; no additional workload or CNI component is installed.

The default remains disabled and adds no new arguments to the old image. When enabled, set `enableNetworkPolicy=true`, select the built agent through `nodeAgent.image.override`, and provide every resource and timeout setting from qualification measurements. Helm rejects missing budgets; the binary independently validates them.

The chart cannot upgrade the EKS managed controller or AWS's add-on schema. Those release dependencies must be qualified separately. This patch is an independently applicable integration change, not a claim that AWS's managed add-on accepts these values today.

Use a dedicated canary node group with appropriate scheduling restrictions. Changing the single cluster-wide `aws-node` DaemonSet value alone is not a per-node rollout strategy. Rollback requires draining/replacing selected nodes or installing equivalent enforcement before disabling interception. In-place removal of FQDN enforcement from running dependent workloads is unsafe.
