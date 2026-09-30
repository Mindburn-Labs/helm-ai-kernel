package admission

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func gatewayChartPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "deploy", "helm-chart"))
	must(t, err)
	return path
}

// renderedBootstrapSQL follows kubelet's ordered env.value expansion on the
// actual hook Job. Secret references are not expanded and need no secret reads.
func renderedBootstrapSQL(t *testing.T, chart string, unmanagedPassword bool) map[string]string {
	t.Helper()
	helm := os.Getenv("KUBE_HELM_CMD")
	if helm == "" {
		helm, _ = exec.LookPath("kube-helm")
		if helm == "" {
			helm = "helm"
		}
	}
	args := []string{"template", "gateway-sql-env", chart, "--show-only", "templates/gateway-migrate-job.yaml"}
	for _, value := range []string{
		"gateway.enabled=true",
		"gateway.tls.existingSecret=gw-tls",
		"gateway.controlPlaneIdentity.jwksURL=https://cp.example.internal/.well-known/jwks.json",
		"gateway.controlPlaneIdentity.issuer=https://cp.example.internal",
		"gateway.controlPlaneIdentity.audience=helm-gateway:smoke",
		"gateway.controlPlaneIdentity.actor=spiffe://helm/control-plane",
		"gateway.database.existingSecret=gw-db",
		"gateway.database.bootstrap.enabled=true",
		"gateway.database.bootstrap.existingSecret=gw-db-admin",
		"gateway.networkPolicy.controlPlane.namespaceSelector.matchLabels.helm-cp=enabled",
		"gateway.networkPolicy.database.to[0].ipBlock.cidr=10.20.30.40/32",
	} {
		args = append(args, "--set", value)
	}
	if unmanagedPassword {
		args = append(args, "--set-string", "gateway.database.bootstrap.runtimePasswordKey=")
	}
	body, err := exec.Command(helm, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("render gateway migrate Job with Kubernetes Helm: %v\n%s", err, body)
	}
	type container struct {
		Name string `yaml:"name"`
		Env  []struct {
			Name      string         `yaml:"name"`
			Value     string         `yaml:"value"`
			ValueFrom map[string]any `yaml:"valueFrom"`
		} `yaml:"env"`
	}
	var job struct {
		Kind string `yaml:"kind"`
		Spec struct {
			Template struct {
				Spec struct {
					InitContainers []container `yaml:"initContainers"`
					Containers     []container `yaml:"containers"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	must(t, decoder.Decode(&job))
	if job.Kind != "Job" {
		t.Fatalf("rendered %q, want the gateway migrate Job", job.Kind)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("expected exactly one rendered Job: %v", err)
	}
	sql := make(map[string]string)
	files := map[string]string{"roles": "001_roles.sql", "grants": "002_grants.sql"}
	for _, c := range append(job.Spec.Template.Spec.InitContainers, job.Spec.Template.Spec.Containers...) {
		file, wanted := files[c.Name]
		if !wanted {
			continue
		}
		values := make(map[string]string)
		for _, env := range c.Env {
			if env.ValueFrom == nil {
				values[env.Name] = kubeletExpand(env.Value, kubeletMappingFuncFor(values))
			}
		}
		if sql[file] != "" || values["HELM_GATEWAY_BOOTSTRAP_SQL"] == "" {
			t.Fatalf("%s: missing or repeated bootstrap SQL environment", c.Name)
		}
		sql[file] = values["HELM_GATEWAY_BOOTSTRAP_SQL"]
	}
	if len(sql) != len(files) {
		t.Fatalf("rendered %d bootstrap SQL environments, want roles and grants", len(sql))
	}
	return sql
}

func TestChartBootstrapSQLSurvivesKubernetesEnvExpansion(t *testing.T) {
	chart := gatewayChartPath(t)
	for _, probe := range []bool{false, true} {
		name := "shipped-sql"
		if probe {
			name = "literal-dollar-probes"
			chart = t.TempDir()
			must(t, os.CopyFS(chart, os.DirFS(gatewayChartPath(t))))
			for _, file := range []string{"001_roles.sql", "002_grants.sql"} {
				path := filepath.Join(chart, "files", "gateway-db", file)
				body, err := os.ReadFile(path)
				must(t, err)
				// The known schema reference would expand without literal-dollar
				// escaping; anonymous/tagged delimiters and terminal $ must survive.
				body = append(body, []byte("\n-- transport probes: $ $$ $$$ $tag$ $1 $(HELM_GATEWAY_SCHEMA) $$(HELM_GATEWAY_SCHEMA) $\n")...)
				must(t, os.WriteFile(path, body, 0600))
			}
		}
		t.Run(name, func(t *testing.T) {
			for _, unmanaged := range []bool{false, true} {
				for file, expanded := range renderedBootstrapSQL(t, chart, unmanaged) {
					expected, err := os.ReadFile(filepath.Join(chart, "files", "gateway-db", file))
					must(t, err)
					if expanded != string(expected) {
						t.Errorf("%s (unmanaged password %v): kubelet expansion changed embedded SQL", file, unmanaged)
					}
				}
			}
		})
	}
}
