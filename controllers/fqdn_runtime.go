package controllers

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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
	BeginFQDNPolicyUpdate(context.Context) error
	EndFQDNPolicyUpdate(context.Context, bool) error
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
	// A successful update in another namespace cannot reopen publication after
	// a failed policy transaction left its namespace's static maps unproven.
	pending map[string]bool
}

func NewFQDNPolicyHandler(k8sClient client.Client, nodeIP string, engine *fqdn.Engine, backend FQDNEndpointResolver) *FQDNPolicyHandler {
	return &FQDNPolicyHandler{client: k8sClient, nodeIP: nodeIP, engine: engine, backend: backend, endpoints: make(map[types.NamespacedName]fqdn.Endpoint), pending: make(map[string]bool)}
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

func (h *FQDNPolicyHandler) apply(ctx context.Context, namespace string, update func() error) (err error) {
	return h.applyWithEnrollment(ctx, namespace, true, update)
}

func (h *FQDNPolicyHandler) applyWithEnrollment(ctx context.Context, namespace string, enroll bool, update func() error) (err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pending[namespace] = true
	if err = h.backend.BeginFQDNPolicyUpdate(ctx); err != nil {
		return err
	}
	success := false
	defer func() {
		if success {
			delete(h.pending, namespace)
		}
		err = errors.Join(err, h.backend.EndFQDNPolicyUpdate(ctx, success && len(h.pending) == 0))
		if err != nil {
			h.pending[namespace] = true
		}
	}()
	// Retire removed owners before changing static maps. The post-update pass
	// also handles new pod attachments and effective CPE changes.
	if err = h.refresh(ctx, namespace, false); err != nil {
		return err
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
		if pod == nil || string(pod.UID) != ep.UID || pod.Status.PodIP != ep.IP.String() {
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
			// Keep the lifetime enrolled when its final domain rule disappears.
			// Removing steering before static policy commits would expose a direct
			// DNS bypass. An empty snapshot revokes grants and dependent flows.
			if err := h.engine.UpdatePolicy(ctx, current, snapshot); err != nil {
				result = errors.Join(result, fmt.Errorf("%s: %w", name, err))
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
		return ctrl.Result{}, h.applyWithEnrollment(ctx, req.Namespace, false, func() error { return nil })
	}
	if !h.localPod(&pod) || !pod.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, h.applyWithEnrollment(ctx, req.Namespace, false, func() error { return nil })
	}
	return ctrl.Result{}, h.apply(ctx, req.Namespace, func() error {
		// A pod may arrive after its PE. Program the observed namespace and
		// cluster tiers before enrolling its new lifetime, including on restart.
		if h.namespaceController == nil || h.clusterController == nil {
			return fmt.Errorf("FQDN policy controllers are not connected")
		}
		var policies policyv1.PolicyEndpointList
		if err := h.client.List(ctx, &policies, client.InNamespace(req.Namespace)); err != nil {
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
			if !h.localPod(before) && !h.localPod(after) {
				return false
			}
			after, ok := e.ObjectNew.(*corev1.Pod)
			if !ok {
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
