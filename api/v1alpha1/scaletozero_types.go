/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ScaleToZeroSpec defines the desired state of ScaleToZero.
type ScaleToZeroSpec struct {
	// serviceRef is the name of the Service to monitor for TCP SYN traffic.
	// +kubebuilder:validation:Required
	ServiceRef string `json:"serviceRef"`

	// deploymentRef is the name of the Deployment to scale.
	// Defaults to the same name as serviceRef.
	// +optional
	DeploymentRef string `json:"deploymentRef,omitempty"`

	// metricsWindowSeconds is the sliding window for SYN count reporting
	// via the External Metrics API. Defaults to 60.
	// +kubebuilder:default=60
	// +kubebuilder:validation:Minimum=10
	// +optional
	MetricsWindowSeconds int32 `json:"metricsWindowSeconds,omitempty"`
}

// ScaleToZeroStatus defines the observed state of ScaleToZero.
type ScaleToZeroStatus struct {
	// proxyMode indicates whether SYN DROP is active (no ready endpoints).
	// +optional
	ProxyMode bool `json:"proxyMode,omitempty"`

	// synCount is the current windowed SYN count.
	// +optional
	SynCount int64 `json:"synCount,omitempty"`

	// lastSynTime is the timestamp of the last observed SYN.
	// +optional
	LastSynTime *metav1.Time `json:"lastSynTime,omitempty"`

	// clusterIP is the resolved ClusterIP of the target Service.
	// +optional
	ClusterIP string `json:"clusterIP,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Service",type=string,JSONPath=`.spec.serviceRef`
// +kubebuilder:printcolumn:name="ProxyMode",type=boolean,JSONPath=`.status.proxyMode`
// +kubebuilder:printcolumn:name="SynCount",type=integer,JSONPath=`.status.synCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ScaleToZero is the Schema for the scaletozeroes API.
// It declares a Service to be monitored by the eBPF traffic observer.
// TCP SYN packets are counted and exposed via the External Metrics API
// for HPA consumption. When no endpoints exist, SYN packets are silently
// dropped to preserve the client's TCP connection while HPA scales up.
type ScaleToZero struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// +required
	Spec ScaleToZeroSpec `json:"spec"`

	// +optional
	Status ScaleToZeroStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// ScaleToZeroList contains a list of ScaleToZero.
type ScaleToZeroList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ScaleToZero `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ScaleToZero{}, &ScaleToZeroList{})
}
