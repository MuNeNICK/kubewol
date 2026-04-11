//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/munenick/kubewol/test/utils"
)

const (
	namespace                   = "kubewol-system"
	projectImage                = "example.com/kubewol:e2e"
	controllerSelector          = "app.kubernetes.io/name=kubewol,app.kubernetes.io/component=controller"
	agentSelector               = "app.kubernetes.io/name=kubewol,app.kubernetes.io/component=agent"
	controllerName              = "kubewol-controller"
	agentName                   = "kubewol-agent"
	controllerServiceAccount    = "kubewol-controller"
	metricsRoleBindingName      = "kubewol-metrics-binding"
	directScaleBindingName      = "kubewol-direct-scale"
	curlPodName                 = "curl-metrics"
	controllerMetricsCheckToken = "controller_runtime_reconcile_total"
	wakeNamespace               = "wake-demo"
	wakeDeploymentName          = "wake-app"
	wakeClientPodName           = "wake-client"
	udpWakeNamespace            = "udp-wake-demo"
	udpWakeDeploymentName       = "udp-echo"
	udpWakeClientPodName        = "udp-client"
)

func TestMain(m *testing.M) {
	if err := buildAndLoadImage(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "e2e setup failed: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestE2ESmoke(t *testing.T) {
	cleanup(t)
	t.Cleanup(func() { cleanup(t) })
	t.Cleanup(func() {
		if t.Failed() {
			dumpDiagnostics(t)
		}
	})

	runOrFail(t, exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage)))

	runOrFail(t, exec.Command("kubectl", "rollout", "status",
		"deployment/"+controllerName, "-n", namespace, "--timeout=5m"))
	runOrFail(t, exec.Command("kubectl", "rollout", "status",
		"daemonset/"+agentName, "-n", namespace, "--timeout=5m"))

	controllerPods := getPods(t, controllerSelector)
	if len(controllerPods) != 1 {
		t.Fatalf("expected 1 controller pod, got %d: %v", len(controllerPods), controllerPods)
	}
	agentPods := getPods(t, agentSelector)
	if len(agentPods) == 0 {
		t.Fatalf("expected at least 1 agent pod, got 0")
	}

	runOrFail(t, exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
		"--clusterrole=kubewol-metrics-reader",
		fmt.Sprintf("--serviceaccount=%s:%s", namespace, controllerServiceAccount)))

	waitFor(t, 2*time.Minute, "controller metrics service endpoints", func() error {
		out, err := run(exec.Command("kubectl", "get", "endpoints", controllerName,
			"-n", namespace, "-o", "jsonpath={.subsets[*].ports[*].port}"))
		if err != nil {
			return err
		}
		if !strings.Contains(out, "8443") {
			return fmt.Errorf("service has no ready 8443 endpoint: %q", out)
		}
		return nil
	})

	runOrFail(t, exec.Command("kubectl", "run", curlPodName,
		"--restart=Never",
		"--namespace", namespace,
		"--image=curlimages/curl:8.12.1",
		"--overrides", curlPodSpec()))

	waitFor(t, 2*time.Minute, "curl pod completion", func() error {
		out, err := run(exec.Command("kubectl", "get", "pod", curlPodName,
			"-n", namespace, "-o", "jsonpath={.status.phase}"))
		if err != nil {
			return err
		}
		if out != "Succeeded" {
			return fmt.Errorf("curl pod phase=%q", out)
		}
		return nil
	})

	metricsOutput := runOrFail(t, exec.Command("kubectl", "logs", curlPodName, "-n", namespace))
	if !strings.Contains(metricsOutput, " 200") {
		t.Fatalf("metrics response did not return HTTP 200:\n%s", metricsOutput)
	}
	if !strings.Contains(metricsOutput, controllerMetricsCheckToken) {
		t.Fatalf("metrics response missing %q:\n%s", controllerMetricsCheckToken, metricsOutput)
	}

	runOrFail(t, exec.Command("kubectl", "apply", "-f", "config/rbac/direct_scale_role.yaml"))
	runOrFailInput(t, wakeWorkloadManifest(), exec.Command("kubectl", "apply", "-f", "-"))

	runOrFail(t, exec.Command("kubectl", "run", wakeClientPodName,
		"--namespace", wakeNamespace,
		"--image=curlimages/curl:8.12.1",
		"--restart=Never",
		"--command", "--", "/bin/sh", "-c", "sleep 300"))

	waitFor(t, 45*time.Second, "wake client ready", func() error {
		out, err := run(exec.Command("kubectl", "get", "pod", wakeClientPodName,
			"-n", wakeNamespace, "-o", "jsonpath={.status.phase}"))
		if err != nil {
			return err
		}
		if out != "Running" {
			return fmt.Errorf("wake client pod phase=%q", out)
		}
		return nil
	})

	time.Sleep(3 * time.Second)

	wakeOutput := runOrFail(t, exec.Command("kubectl", "exec", "-n", wakeNamespace, wakeClientPodName,
		"--", "curl", "-sS", "--max-time", "30",
		fmt.Sprintf("http://%s.%s.svc.cluster.local/", wakeDeploymentName, wakeNamespace)))

	waitFor(t, 45*time.Second, "direct-scale target deployment to scale to 1", func() error {
		out, err := run(exec.Command("kubectl", "get", "deployment", wakeDeploymentName,
			"-n", wakeNamespace, "-o", "jsonpath={.spec.replicas}:{.status.readyReplicas}"))
		if err != nil {
			return err
		}
		if out != "1:1" {
			return fmt.Errorf("deployment replicas not ready yet: %q", out)
		}
		return nil
	})

	if !strings.Contains(wakeOutput, "wake-ok") {
		t.Fatalf("wake client did not receive expected response:\n%s", wakeOutput)
	}

	time.Sleep(10 * time.Second)
	terminating := runOrFail(t, exec.Command("kubectl", "get", "pods", "-n", wakeNamespace,
		"-l", "app=wake-app",
		"-o", "jsonpath={range .items[*]}{.metadata.deletionTimestamp}{\"\\n\"}{end}"))
	if strings.TrimSpace(terminating) != "" {
		t.Fatalf("wake target pod entered terminating unexpectedly: %q", terminating)
	}
}

func TestE2EUDPWake(t *testing.T) {
	cleanup(t)
	t.Cleanup(func() { cleanup(t) })
	t.Cleanup(func() {
		if t.Failed() {
			dumpDiagnostics(t)
		}
	})

	runOrFail(t, exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage)))

	runOrFail(t, exec.Command("kubectl", "rollout", "status",
		"deployment/"+controllerName, "-n", namespace, "--timeout=5m"))
	runOrFail(t, exec.Command("kubectl", "rollout", "status",
		"daemonset/"+agentName, "-n", namespace, "--timeout=5m"))

	runOrFail(t, exec.Command("kubectl", "apply", "-f", "config/rbac/direct_scale_role.yaml"))
	runOrFailInput(t, udpWakeWorkloadManifest(), exec.Command("kubectl", "apply", "-f", "-"))

	runOrFail(t, exec.Command("kubectl", "run", udpWakeClientPodName,
		"--namespace", udpWakeNamespace,
		"--image=python:3.12-alpine",
		"--restart=Never",
		"--command", "--", "/bin/sh", "-c", "sleep 300"))

	waitFor(t, 45*time.Second, "udp wake client ready", func() error {
		out, err := run(exec.Command("kubectl", "get", "pod", udpWakeClientPodName,
			"-n", udpWakeNamespace, "-o", "jsonpath={.status.phase}"))
		if err != nil {
			return err
		}
		if out != "Running" {
			return fmt.Errorf("udp wake client pod phase=%q", out)
		}
		return nil
	})

	time.Sleep(3 * time.Second)

	firstUDPAttempt := exec.Command("kubectl", "exec", "-n", udpWakeNamespace, udpWakeClientPodName,
		"--", "python", "-c", udpClientScript("first"))
	firstOutput, err := run(firstUDPAttempt)
	if err == nil {
		t.Fatalf("expected first UDP datagram to fail while triggering wake, output=%q", strings.TrimSpace(firstOutput))
	}

	waitFor(t, 45*time.Second, "udp direct-scale target deployment to scale to 1", func() error {
		out, err := run(exec.Command("kubectl", "get", "deployment", udpWakeDeploymentName,
			"-n", udpWakeNamespace, "-o", "jsonpath={.spec.replicas}:{.status.readyReplicas}"))
		if err != nil {
			return err
		}
		if out != "1:1" {
			return fmt.Errorf("udp deployment replicas not ready yet: %q", out)
		}
		return nil
	})

	secondOutput := runOrFail(t, exec.Command("kubectl", "exec", "-n", udpWakeNamespace, udpWakeClientPodName,
		"--", "python", "-c", udpClientScript("second")))
	if !strings.Contains(secondOutput, "udp-ok:second") {
		t.Fatalf("udp wake client did not receive expected response:\n%s", secondOutput)
	}
}

func buildAndLoadImage() error {
	if _, err := utils.Run(exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", projectImage))); err != nil {
		return err
	}
	return utils.LoadImageToKindClusterWithName(projectImage)
}

func cleanup(t *testing.T) {
	t.Helper()
	runIgnore(exec.Command("kubectl", "delete", "clusterrolebinding", metricsRoleBindingName, "--ignore-not-found"))
	runIgnore(exec.Command("kubectl", "delete", "clusterrolebinding", directScaleBindingName, "--ignore-not-found"))
	runIgnore(exec.Command("kubectl", "delete", "pod", curlPodName, "-n", namespace, "--ignore-not-found"))
	runIgnore(exec.Command("kubectl", "delete", "namespace", wakeNamespace, "--ignore-not-found"))
	runIgnore(exec.Command("kubectl", "delete", "namespace", udpWakeNamespace, "--ignore-not-found"))
	runIgnore(exec.Command("make", "undeploy", "ignore-not-found=true"))
}

func dumpDiagnostics(t *testing.T) {
	t.Helper()
	logCommand(t, "kubectl", "get", "pods", "-n", namespace, "-o", "wide")
	logCommand(t, "kubectl", "describe", "deployment", controllerName, "-n", namespace)
	logCommand(t, "kubectl", "describe", "daemonset", agentName, "-n", namespace)
	for _, pod := range getPodsMaybe(controllerSelector) {
		logCommand(t, "kubectl", "logs", pod, "-n", namespace, "--all-containers=true")
	}
	for _, pod := range getPodsMaybe(agentSelector) {
		logCommand(t, "kubectl", "logs", pod, "-n", namespace, "--all-containers=true")
	}
	logCommand(t, "kubectl", "logs", curlPodName, "-n", namespace)
	logCommand(t, "kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
	logCommand(t, "kubectl", "get", "all", "-n", wakeNamespace)
	logCommand(t, "kubectl", "logs", wakeClientPodName, "-n", wakeNamespace)
	logCommand(t, "kubectl", "get", "events", "-n", wakeNamespace, "--sort-by=.lastTimestamp")
	logCommand(t, "kubectl", "get", "all", "-n", udpWakeNamespace)
	logCommand(t, "kubectl", "logs", udpWakeClientPodName, "-n", udpWakeNamespace)
	logCommand(t, "kubectl", "get", "events", "-n", udpWakeNamespace, "--sort-by=.lastTimestamp")
}

func getPods(t *testing.T, selector string) []string {
	t.Helper()
	out := runOrFail(t, exec.Command("kubectl", "get", "pods",
		"-n", namespace,
		"-l", selector,
		"-o", "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}"))
	return utils.GetNonEmptyLines(out)
}

func getPodsMaybe(selector string) []string {
	out, err := run(exec.Command("kubectl", "get", "pods",
		"-n", namespace,
		"-l", selector,
		"-o", "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}"))
	if err != nil {
		return nil
	}
	return utils.GetNonEmptyLines(out)
}

func waitFor(t *testing.T, timeout time.Duration, desc string, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := fn(); err == nil {
			return
		} else {
			lastErr = err
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("timed out waiting for %s: %v", desc, lastErr)
}

func runOrFail(t *testing.T, cmd *exec.Cmd) string {
	t.Helper()
	out, err := run(cmd)
	if err != nil {
		t.Fatalf("%s failed: %v", strings.Join(cmd.Args, " "), err)
	}
	return strings.TrimSpace(out)
}

func runOrFailInput(t *testing.T, input string, cmd *exec.Cmd) string {
	t.Helper()
	cmd.Stdin = strings.NewReader(input)
	out, err := run(cmd)
	if err != nil {
		t.Fatalf("%s failed: %v", strings.Join(cmd.Args, " "), err)
	}
	return strings.TrimSpace(out)
}

func runIgnore(cmd *exec.Cmd) {
	_, _ = run(cmd)
}

func logCommand(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := run(exec.Command(name, args...))
	if err != nil {
		t.Logf("%s failed: %v", strings.Join(append([]string{name}, args...), " "), err)
		return
	}
	t.Logf("%s:\n%s", strings.Join(append([]string{name}, args...), " "), out)
}

func run(cmd *exec.Cmd) (string, error) {
	return utils.Run(cmd)
}

func curlPodSpec() string {
	return fmt.Sprintf(`{
  "apiVersion": "v1",
  "spec": {
    "serviceAccountName": %q,
    "restartPolicy": "Never",
    "containers": [{
      "name": "curl",
      "image": "curlimages/curl:8.12.1",
      "command": ["/bin/sh", "-c"],
      "args": ["TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); curl -sSki -H \"Authorization: Bearer ${TOKEN}\" https://%s.%s.svc.cluster.local:8443/metrics"],
      "securityContext": {
        "allowPrivilegeEscalation": false,
        "readOnlyRootFilesystem": true,
        "runAsNonRoot": true,
        "runAsUser": 1000,
        "capabilities": {
          "drop": ["ALL"]
        },
        "seccompProfile": {
          "type": "RuntimeDefault"
        }
      }
    }]
  }
}`, controllerServiceAccount, controllerName, namespace)
}

func wakeWorkloadManifest() string {
	return fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s
  namespace: %s
  labels:
    app: wake-app
spec:
  replicas: 0
  selector:
    matchLabels:
      app: wake-app
  template:
    metadata:
      labels:
        app: wake-app
    spec:
      containers:
        - name: web
          image: hashicorp/http-echo:1.0.0
          args:
            - "-text=wake-ok"
            - "-listen=:8080"
          ports:
            - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: %s
  namespace: %s
  annotations:
    kubewol/enabled: "true"
    kubewol/direct-scale: "true"
spec:
  selector:
    app: wake-app
  ports:
    - name: http
      port: 80
      targetPort: 8080
`, wakeNamespace, wakeDeploymentName, wakeNamespace, wakeDeploymentName, wakeNamespace)
}

func udpWakeWorkloadManifest() string {
	return fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s
  namespace: %s
  labels:
    app: udp-echo
spec:
  replicas: 0
  selector:
    matchLabels:
      app: udp-echo
  template:
    metadata:
      labels:
        app: udp-echo
    spec:
      containers:
        - name: udp-echo
          image: python:3.12-alpine
          command: ["python", "-c"]
          args:
            - |
              import socket
              sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
              sock.bind(("0.0.0.0", 9999))
              while True:
                  data, addr = sock.recvfrom(4096)
                  sock.sendto(b"udp-ok:" + data, addr)
          ports:
            - containerPort: 9999
              protocol: UDP
---
apiVersion: v1
kind: Service
metadata:
  name: %s
  namespace: %s
  annotations:
    kubewol/enabled: "true"
    kubewol/direct-scale: "true"
spec:
  selector:
    app: udp-echo
  ports:
    - name: udp
      port: 9999
      targetPort: 9999
      protocol: UDP
`, udpWakeNamespace, udpWakeDeploymentName, udpWakeNamespace, udpWakeDeploymentName, udpWakeNamespace)
}

func udpClientScript(payload string) string {
	return fmt.Sprintf(`import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1)
sock.sendto(%q.encode(), ("%s.%s.svc.cluster.local", 9999))
data, _ = sock.recvfrom(4096)
print(data.decode())
`, payload, udpWakeDeploymentName, udpWakeNamespace)
}
