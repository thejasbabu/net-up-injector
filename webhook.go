package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
	"html/template"
	"io/ioutil"
	"k8s.io/api/admission/v1beta1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"net/http"
	"strings"
)

var (
	runtimeScheme                           = runtime.NewScheme()
	codecs                                  = serializer.NewCodecFactory(runtimeScheme)
	deserializer                            = codecs.UniversalDeserializer()
	packetSnifferAdmissionAnnotation        = "thejasbabu.packetSniffer.inject"
	packetSnifferAdmissionStatusAnnotation  = "thejasbabu.packetSniffer.status"
	packetSnifferNetworkInterfaceAnnotation = "thejasbabu.packetSniffer.networkInterface"
	packetSnifferBPFExprAnnotation          = "thejasbabu.packetSniffer.bpfExpr"
	defaultBPFExpr                          = "tcp and dst port 80"
	defaultNetworkInterface                 = "eth0"
	ignoredNamespaces                       = []string{
		metav1.NamespaceSystem,
	}
)

type WebHookServer struct {
	server         *http.Server
	configFilePath string
	image          string
}

type SidecarConfig struct {
	Image            string
	BPFExpr          string
	NetworkInterface string
	Output           string
	LogLevel         string
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func NewWebHookServer(server *http.Server, configFilePath string, image string) WebHookServer {
	return WebHookServer{server: server, configFilePath: configFilePath, image: image}
}

func (ws *WebHookServer) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		zap.S().Errorf("empty request body")
		http.Error(w, "Empty body", http.StatusBadRequest)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		zap.S().Errorf("invalid Content-Type, expected `application/json` but got Content-Type=%s", contentType)
		http.Error(w, "Invalid Content-Type", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *v1beta1.AdmissionResponse
	review := v1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &review); err != nil {
		zap.S().Errorf("could not deserialize body: %s", err.Error())
		admissionResponse = &v1beta1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		if r.URL.Path == "/mutate" {
			zap.L().Debug("received request for mutation")
			admissionResponse = ws.mutate(&review)
		}
	}

	admissionReview := v1beta1.AdmissionReview{}
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if review.Request != nil {
			admissionReview.Response.UID = review.Request.UID
		}
	}

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		zap.S().Errorf("could not marshal the admission review: %s", err.Error())
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}

	if _, err := w.Write(resp); err != nil {
		zap.S().Errorf("could not write the response: %s", err.Error())
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}

func (ws *WebHookServer) mutate(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := ar.Request
	var resourceNamespace, resourceName string
	var availableAnnotations map[string]string

	zap.S().Debugf("AdmissionReview for Kind=%v, Namespace=%v Name=%v UID=%v patchOperation=%v UserInfo=%v\n", req.Kind, req.Namespace, req.Name, req.UID, req.Operation, req.UserInfo)
	var pod v1.Pod
	switch req.Kind.Kind {
	case "Pod":
		if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
			zap.S().Errorf("could not parse the raw object for pod: %s", err.Error())
			return &v1beta1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: err.Error(),
				},
			}
		}
		objectMeta := &pod.ObjectMeta
		resourceName, resourceNamespace, availableAnnotations = objectMeta.Name, req.Namespace, objectMeta.Annotations
	}

	if !mutationRequired(resourceNamespace, availableAnnotations) {
		zap.S().Debugf("skipping mutation for %s in %s namespace because of policy check", resourceName, resourceNamespace)
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}
	annotations := map[string]string{packetSnifferAdmissionStatusAnnotation: "injected"}
	patchBytes, err := ws.createPatch(availableAnnotations, annotations, pod)
	if err != nil {
		zap.S().Errorf("could not create a patch for %s in %s namespace: %s", resourceName, resourceNamespace, err.Error())
		return &v1beta1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}
	zap.S().Debugf("AdmissionResponse: Applied successfully for application %s in namespace %s", resourceName, resourceNamespace)
	return &v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

func mutationRequired(namespaceName string, annotations map[string]string) bool {
	var required bool
	if checkNamespaceIsValid(namespaceName) {
		if annotations == nil {
			annotations = map[string]string{}
		}
		switch strings.ToLower(annotations[packetSnifferAdmissionAnnotation]) {
		case "enabled", "true":
			required = true
		default:
			required = false
		}
	}
	return required
}

func checkNamespaceIsValid(namespace string) bool {
	for _, ignoreNamespace := range ignoredNamespaces {
		if namespace == ignoreNamespace {
			return false
		}
	}
	return true
}

func (ws WebHookServer) createPatch(availableAnnotations map[string]string, annotations map[string]string, pod v1.Pod) ([]byte, error) {
	var patch []patchOperation
	container := ws.sidecarContainerConfig(availableAnnotations)
	patch = append(patch, updatePodSpec(container)...)
	patch = append(patch, updateAnnotation(annotations)...)
	return json.Marshal(patch)
}

func (ws *WebHookServer) sidecarContainerConfig(availableAnnotations map[string]string) v1.Container {
	networkInterface, ok := availableAnnotations[packetSnifferNetworkInterfaceAnnotation]
	if !ok {
		zap.S().Infof("%s annotation is missing, using default %s interface", packetSnifferNetworkInterfaceAnnotation, defaultNetworkInterface)
		networkInterface = defaultNetworkInterface
	}
	bpfExpr, ok := availableAnnotations[packetSnifferBPFExprAnnotation]
	if !ok {
		zap.S().Infof("%s annotation is missing, using default %s expr", packetSnifferBPFExprAnnotation, defaultBPFExpr)
		bpfExpr = defaultBPFExpr
	}
	config := SidecarConfig{Image: ws.image, BPFExpr: bpfExpr, NetworkInterface: networkInterface, Output: "stdout", LogLevel: "info"}
	files, err := template.ParseFiles(ws.configFilePath)
	if err != nil {
		zap.S().Errorf("could not parse the config file %s: %s", ws.configFilePath, err.Error())
		return v1.Container{}
	}
	var buf bytes.Buffer

	err = files.Execute(&buf, config)
	if err != nil {
		zap.S().Errorf("could not parse the config file %s: %s", ws.configFilePath, err.Error())
		return v1.Container{}
	}
	var container v1.Container
	err = yaml.Unmarshal(buf.Bytes(), &container)
	if err != nil {
		zap.S().Errorf("could not unmarshal yaml to container object: %s", ws.configFilePath, err.Error())
		return v1.Container{}
	}
	return container
}

func updateAnnotation(added map[string]string) (patch []patchOperation) {
	for key, value := range added {
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  "/metadata/annotations/" + key,
			Value: value,
		})
	}
	return patch
}

func updatePodSpec(container v1.Container) (patch []patchOperation) {
	if container.Image != "" {
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  "/spec/containers/-",
			Value: container,
		})
	}
	return patch
}
