package controllers

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"

	policyv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/fqdn"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

type FQDNEndpointResolver interface {
	ResolveFQDNEndpoint(context.Context, *corev1.Pod, string) (fqdn.Endpoint, error)
	BeginFQDNPolicyUpdateFor(context.Context, string, []string) error
	EndFQDNPolicyUpdateFor(context.Context, string, bool) error
}

// FQDNPolicyHandler is shared by PE, CPE and Pod controllers. Its short-lived
// staging gate prevents publication against a mixture of old shared static maps
// and new endpoint-local policy. The backend fences every kernel mutation.
type FQDNPolicyHandler struct {
	client              client.Client
	nodeIP              string
	engine              *fqdn.Engine
	backend             FQDNEndpointResolver
	mu                  sync.Mutex
	endpoints           map[types.NamespacedName]fqdn.Endpoint
	namespaceController *PolicyEndpointsReconciler
	clusterController   *ClusterPolicyEndpointsReconciler
}

func NewFQDNPolicyHandler(k8sClient client.Client, nodeIP string, engine *fqdn.Engine, backend FQDNEndpointResolver) *FQDNPolicyHandler {
	return &FQDNPolicyHandler{client: k8sClient, nodeIP: nodeIP, engine: engine, backend: backend, endpoints: make(map[types.NamespacedName]fqdn.Endpoint)}
}

func (r *PolicyEndpointsReconciler) SetFQDNPolicyHandler(handler *FQDNPolicyHandler) {
	r.fqdnPolicyHandler = handler
	if handler != nil {
		handler.namespaceController = r
	}
}

func (r *ClusterPolicyEndpointsReconciler) SetFQDNPolicyHandler(handler *FQDNPolicyHandler) {
	r.fqdnPolicyHandler = handler
	if handler != nil {
		handler.clusterController = r
	}
}

func (h *FQDNPolicyHandler) apply(ctx context.Context, namespace, transaction string, update func() error) (err error) {
	return h.applyWithEnrollment(ctx, namespace, transaction, true, update)
}

func (h *FQDNPolicyHandler) applyWithEnrollment(ctx context.Context, namespace, transaction string, enroll bool, update func() error) (err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	scope, scopeErr := h.policyScope(ctx, namespace)
	if err = h.backend.BeginFQDNPolicyUpdateFor(ctx, transaction, scope); err != nil {
		return err
	}
	success := false
	defer func() {
		err = errors.Join(err, h.backend.EndFQDNPolicyUpdateFor(ctx, transaction, success))
	}()
	if scopeErr != nil {
		return scopeErr
	}
	// Retire removed owners before changing static maps. The post-update pass
	// also handles new pod attachments and effective CPE changes.
	if preErr := h.refresh(ctx, namespace, false); preErr != nil {
		// Staging already made the datapath restrictive. An old attachment
		// can be missing precisely because this reconcile needs to repair it.
		// Require the final refresh to prove success after static repair.
		log().Errorf("FQDN pre-update revocation requires retry after static programming: %v", preErr)
	}
	if err = update(); err != nil {
		return err
	}
	if err = h.refresh(ctx, namespace, enroll); err != nil {
		return err
	}
	success = true
	return nil
}

// Include existing lifetimes (including removed pods) and potential new
// enrollments. Backend staging tracks each transaction separately, so a failed
// policy cannot be reopened by another transaction that shares a static map.
func (h *FQDNPolicyHandler) policyScope(ctx context.Context, namespace string) ([]string, error) {
	ids := make(map[string]bool)
	for name, ep := range h.endpoints {
		if namespace == "" || name.Namespace == namespace {
			ids[ep.PodIdentifier] = true
		}
	}
	var pods corev1.PodList
	err := h.client.List(ctx, &pods, client.InNamespace(namespace))
	if err == nil {
		for i := range pods.Items {
			pod := &pods.Items[i]
			if h.localPod(pod) {
				ids[utils.GetPodIdentifier(pod.Name, pod.Namespace)] = true
			}
		}
	}
	result := make([]string, 0, len(ids))
	for id := range ids {
		result = append(result, id)
	}
	sort.Strings(result)
	return result, err
}

// refresh runs under h.mu. A cache/read/programming failure is returned and
// leaves selected DNS blocked. Malformed contributors are removed while their
// independently valid siblings remain eligible; ordinary PE isolation survives.
func (h *FQDNPolicyHandler) refresh(ctx context.Context, namespace string, enroll bool) error {
	var policies policyv1.PolicyEndpointList
	var pods corev1.PodList
	if err := h.client.List(ctx, &policies, client.InNamespace(namespace)); err != nil {
		return err
	}
	if err := h.client.List(ctx, &pods, client.InNamespace(namespace)); err != nil {
		return err
	}
	live := make(map[types.NamespacedName]*corev1.Pod)
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.HostIP == h.nodeIP && !pod.Spec.HostNetwork && pod.DeletionTimestamp.IsZero() && pod.UID != "" && pod.Status.PodIP != "" {
			live[types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}] = pod
		}
	}
	var result error
	for name, ep := range h.endpoints {
		if namespace != "" && name.Namespace != namespace {
			continue
		}
		pod := live[name]
		current, alive := h.engine.Lookup(ep.IfIndex, ep.IP)
		if pod == nil || string(pod.UID) != ep.UID || pod.Status.PodIP != ep.IP.String() || !alive || current != ep {
			if err := h.engine.Delete(ctx, ep); err != nil {
				result = errors.Join(result, err)
				continue
			}
			delete(h.endpoints, name)
		}
	}
	for name, pod := range live {
		var previous []fqdn.Rule
		if current, ok := h.endpoints[name]; ok {
			if diagnostic, err := h.engine.Inspect(current); err == nil {
				previous = diagnostic.Rules
			}
		}
		snapshot, compileErr := compileFQDNPolicyBounded(pod, policies.Items, h.nodeIP, h.engine.Limits(), previous)
		if compileErr != nil {
			// The snapshot contains only independently valid contributors. Apply it
			// even when one rule is invalid, so errors never retain removed grants.
			log().Errorf("Rejected FQDN policy contributions for %s: %v", name, compileErr)
		}
		if current, ok := h.endpoints[name]; ok {
			if string(pod.UID) != current.UID {
				continue
			} // old deletion failed
			if enroll {
				resolved, err := h.backend.ResolveFQDNEndpoint(ctx, pod, utils.GetPodIdentifier(pod.Name, pod.Namespace))
				if err != nil {
					result = errors.Join(result, err)
					continue
				}
				if resolved.IfIndex != current.IfIndex || resolved.IP != current.IP {
					// CNI repair can recreate a veth without changing pod UID/IP.
					// Retire the old interface lifetime before binding its successor.
					if err := h.engine.Delete(ctx, current); err != nil {
						result = errors.Join(result, err)
						continue
					}
					delete(h.endpoints, name)
					replacement, err := h.engine.Enroll(ctx, resolved, snapshot)
					if err != nil {
						result = errors.Join(result, err)
						continue
					}
					h.endpoints[name] = replacement
					continue
				}
			}
			// Keep the lifetime enrolled when its final domain rule disappears.
			// Removing steering before static policy commits would expose a direct
			// DNS bypass. An empty snapshot revokes grants and dependent flows.
			if err := h.engine.UpdatePolicy(ctx, current, snapshot); err != nil {
				if fqdn.IsPolicyRejected(err) {
					// The engine committed a restrictive surviving subset. Retrying
					// it as a failed kernel transaction would keep all selected DNS
					// blocked even though the removed permissions were revoked.
					log().Errorf("Rejected FQDN policy contribution for %s: %v", name, err)
				} else {
					result = errors.Join(result, fmt.Errorf("%s: %w", name, err))
				}
			}
			continue
		}
		if !enroll || len(snapshot.Rules) == 0 {
			continue
		}
		ep, err := h.backend.ResolveFQDNEndpoint(ctx, pod, utils.GetPodIdentifier(pod.Name, pod.Namespace))
		if err != nil {
			result = errors.Join(result, fmt.Errorf("%s: %w", name, err))
			continue
		}
		ep, err = h.engine.Enroll(ctx, ep, snapshot)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("%s: %w", name, err))
			continue
		}
		h.endpoints[name] = ep
	}
	return result
}

// Pod UID/IP/deletion changes must retire DNS state even if no PE update is
// delivered. CNI lifecycle checks independently invalidate detached interfaces.
func (h *FQDNPolicyHandler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pod corev1.Pod
	if err := h.client.Get(ctx, req.NamespacedName, &pod); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		// PE selectors can briefly retain a deleted pod. Retire its lifetime
		// immediately without trying to attach probes to that stale selector.
		return ctrl.Result{}, h.applyWithEnrollment(ctx, req.Namespace, "pod/"+req.String(), false, func() error { return nil })
	}
	if !h.localPod(&pod) || !pod.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, h.applyWithEnrollment(ctx, req.Namespace, "pod/"+req.String(), false, func() error { return nil })
	}
	// Initial enrollment also synchronizes CPEs, whose selectors can span
	// namespaces; stage every group those shared map updates can affect.
	return ctrl.Result{}, h.apply(ctx, "", "pod/"+req.String(), func() error {
		// A pod may arrive after its PE. Program the observed namespace and
		// cluster tiers before enrolling its new lifetime, including on restart.
		if h.namespaceController == nil || h.clusterController == nil {
			return fmt.Errorf("FQDN policy controllers are not connected")
		}
		var policies policyv1.PolicyEndpointList
		if err := h.client.List(ctx, &policies); err != nil {
			return err
		}
		for i := range policies.Items {
			if policies.Items[i].DeletionTimestamp.IsZero() {
				if err := h.namespaceController.reconcilePolicyEndpoint(ctx, &policies.Items[i]); err != nil {
					return err
				}
			}
		}
		var clusterPolicies policyv1.ClusterPolicyEndpointList
		if err := h.client.List(ctx, &clusterPolicies); err != nil {
			return err
		}
		for i := range clusterPolicies.Items {
			if clusterPolicies.Items[i].DeletionTimestamp.IsZero() {
				if err := h.clusterController.reconcileClusterPolicyEndpoint(ctx, &clusterPolicies.Items[i]); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (h *FQDNPolicyHandler) SetupWithManager(_ context.Context, mgr ctrl.Manager) error {
	local := func(obj client.Object) bool { pod, ok := obj.(*corev1.Pod); return ok && h.localPod(pod) }
	changes := predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return local(e.Object) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return local(e.Object) },
		GenericFunc: func(e event.GenericEvent) bool { return local(e.Object) },
		UpdateFunc: func(e event.UpdateEvent) bool {
			before, ok := e.ObjectOld.(*corev1.Pod)
			if !ok {
				return false
			}
			after, ok := e.ObjectNew.(*corev1.Pod)
			if !ok {
				return false
			}
			if !h.localPod(before) && !h.localPod(after) {
				return false
			}
			return before.UID != after.UID || before.Status.PodIP != after.Status.PodIP || before.Status.HostIP != after.Status.HostIP ||
				!reflect.DeepEqual(before.DeletionTimestamp, after.DeletionTimestamp) || !reflect.DeepEqual(before.Labels, after.Labels)
		}}
	return ctrl.NewControllerManagedBy(mgr).Named("fqdn-pod-lifetimes").For(&corev1.Pod{}).WithEventFilter(changes).Complete(h)
}

func (h *FQDNPolicyHandler) localPod(pod *corev1.Pod) bool {
	return pod.Status.HostIP == h.nodeIP && !pod.Spec.HostNetwork && pod.Status.PodIP != ""
}
