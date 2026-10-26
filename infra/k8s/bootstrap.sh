#!/usr/bin/env bash
# One-time cluster and CI setup for mcp-cimd. Idempotent: re-running it is
# safe and is the quickest way to check the setup is still intact.
#
#   ./infra/k8s/bootstrap.sh                 # show what is and is not set up
#   ./infra/k8s/bootstrap.sh --apply         # do the missing pieces
#
# Needs an interactive kubectl session (this cluster authenticates through an
# OIDC exec plugin that opens a browser) and gh logged in to the repo. Run it
# yourself; it cannot be done from a non-interactive agent.
#
# The ServiceAccount token it reads is written only to a file with mode 600
# and handed to `gh secret set` over stdin. It is never printed.
set -uo pipefail

NS="${K8S_NAMESPACE:-ping-devops-robpieper}"
REPO="${GH_REPO:-robpieperping/mcp-cimd}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
APPLY=no
[ "${1:-}" = "--apply" ] && APPLY=yes

todo=0
step() { printf '\n== %s\n' "$1"; }
have() { printf '   ok      %s\n' "$1"; }
need() { printf '   MISSING %s\n' "$1"; todo=$((todo+1)); }
did()  { printf '   done    %s\n' "$1"; }
warn() { printf '   note    %s\n' "$1"; }

for tool in kubectl gh; do
  command -v "$tool" >/dev/null || { echo "bootstrap.sh needs $tool on PATH." >&2; exit 2; }
done

if ! kubectl --request-timeout=20s auth whoami >/dev/null 2>&1; then
  echo "kubectl cannot reach the cluster. This cluster uses an interactive OIDC" >&2
  echo "exec plugin, so run 'kubectl get ns' once in a terminal and complete the" >&2
  echo "browser login first." >&2
  exit 2
fi
printf 'cluster: %s\nnamespace: %s\nrepo: %s\nmode: %s\n' \
  "$(kubectl config current-context)" "$NS" "$REPO" \
  "$([ "$APPLY" = yes ] && echo apply || echo "report only (pass --apply to change things)")"

# ── 1. CI deploy identity ────────────────────────────────────────────────────

step "CI ServiceAccount"
if kubectl get sa github-deployer -n "$NS" >/dev/null 2>&1; then
  have "ServiceAccount github-deployer exists"
else
  need "ServiceAccount github-deployer"
  if [ "$APPLY" = yes ]; then
    kubectl apply -n "$NS" -f "$HERE/ci-rbac.yaml"
    did "applied ci-rbac.yaml"
  fi
fi

# The Role is shared with the other repos in this program, and kubectl apply
# fails the WHOLE deploy on the first forbidden resource -- which presents as
# a deploy failure rather than an RBAC one. Check each verb this manifest
# actually needs.
if kubectl get role github-deployer -n "$NS" >/dev/null 2>&1; then
  for res in deployments.apps services ingresses.networking.k8s.io; do
    if kubectl auth can-i patch "$res" -n "$NS" \
         --as "system:serviceaccount:$NS:github-deployer" 2>/dev/null | grep -q yes; then
      have "github-deployer may patch $res"
    else
      need "github-deployer may patch $res -- extend the Role in ci-rbac.yaml"
    fi
  done
  # It must NOT be able to read the application secret.
  if kubectl auth can-i get secrets -n "$NS" \
       --as "system:serviceaccount:$NS:github-deployer" 2>/dev/null | grep -q yes; then
    need "github-deployer can read Secrets -- it should not be able to"
  else
    have "github-deployer cannot read Secrets (deliberate)"
  fi
fi

# ── 2. GitHub Actions secrets ────────────────────────────────────────────────

step "GitHub Actions secrets"
existing=$(gh secret list --repo "$REPO" 2>/dev/null | awk '{print $1}')

# KUBE_CONFIG_B64 is the only secret the deploy needs. The workflow defaults
# the namespace in its env block, since a namespace name is not a credential.
if printf '%s\n' "$existing" | grep -qx KUBE_CONFIG_B64; then
  have "KUBE_CONFIG_B64 is set"
else
  need "KUBE_CONFIG_B64 -- the only secret the deploy needs"
fi
if printf '%s\n' "$existing" | grep -qx K8S_NAMESPACE; then
  have "K8S_NAMESPACE is set (optional; overrides the workflow default)"
else
  warn "K8S_NAMESPACE not set -- the workflow defaults to $NS, which is fine"
fi

if [ "$APPLY" = yes ]; then
  if ! printf '%s\n' "$existing" | grep -qx KUBE_CONFIG_B64; then
    # Built from the ServiceAccount token, NOT from the human kubeconfig:
    # the OIDC exec plugin needs a browser and cannot work in Actions.
    server=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
    ca=$(kubectl get secret github-deployer-token -n "$NS" -o jsonpath='{.data.ca\.crt}')
    token=$(kubectl get secret github-deployer-token -n "$NS" -o jsonpath='{.data.token}' | base64 -d)
    if [ -z "$token" ]; then
      need "github-deployer-token holds no token yet -- wait a moment and re-run"
    else
      kube=$(mktemp); chmod 600 "$kube"
      cat > "$kube" <<CFG
apiVersion: v1
kind: Config
clusters:
- name: target
  cluster: { server: ${server}, certificate-authority-data: ${ca} }
contexts:
- name: ci
  context: { cluster: target, namespace: ${NS}, user: github-deployer }
current-context: ci
users:
- name: github-deployer
  user: { token: ${token} }
CFG
      # Prove it works before handing it to CI.
      if KUBECONFIG="$kube" kubectl --request-timeout=20s auth whoami >/dev/null 2>&1; then
        base64 < "$kube" | tr -d '\n' | gh secret set KUBE_CONFIG_B64 --repo "$REPO" --body-file -
        did "set KUBE_CONFIG_B64 (verified against the cluster first)"
      else
        need "the generated kubeconfig does not authenticate -- not uploading it"
      fi
      rm -f "$kube"
      unset token
    fi
  fi
fi

# ── 3. Application secret ────────────────────────────────────────────────────

step "Application Secret mcp-cimd-secrets"
if kubectl get secret mcp-cimd-secrets -n "$NS" >/dev/null 2>&1; then
  keys=$(kubectl get secret mcp-cimd-secrets -n "$NS" -o jsonpath='{.data}' \
         | tr ',' '\n' | sed -n 's/.*"\([A-Z_]*\)":.*/\1/p' | tr '\n' ' ')
  have "exists, keys: ${keys:-unknown}"
  case "$keys" in
    *FHIR_BASE_URL*) have "carries FHIR_BASE_URL" ;;
    *)               need "FHIR_BASE_URL is not in the Secret" ;;
  esac
else
  need "Secret mcp-cimd-secrets"
  if [ "$APPLY" = yes ]; then
    if [ -f "$ROOT/.env" ] && grep -q '^FHIR_BASE_URL=' "$ROOT/.env"; then
      # Only the outbound settings belong here. MCP_RESOURCE, OAUTH_ISSUER
      # and MCP_TOOLSET are public identifiers and live in the Deployment's
      # env block, where a change shows up in a diff.
      kubectl create secret generic mcp-cimd-secrets -n "$NS" \
        $(grep -E '^(FHIR_BASE_URL|PINGONE_[A-Z_]+)=.' "$ROOT/.env" \
          | sed 's/^/--from-literal=/') \
        --dry-run=client -o yaml | kubectl apply -f -
      did "created from .env (FHIR_BASE_URL and any PINGONE_* values)"
    else
      need "no FHIR_BASE_URL in $ROOT/.env -- copy .env.example and fill it in"
    fi
  fi
fi

# ── 4. Container image ───────────────────────────────────────────────────────

step "GHCR package"
raw=$(gh api "user/packages/container/mcp-cimd" 2>&1)
pkg=$(printf '%s' "$raw" | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('visibility',''))
except Exception: pass" 2>/dev/null)
case "$pkg" in public|private|internal) ;; *) pkg="" ;; esac

if printf '%s' "$raw" | grep -q 'read:packages scope'; then
  # The default gh token does not carry it, and without it neither the
  # check below nor the visibility flip can work.
  need "gh token lacks the packages scope, so visibility cannot be read"
  warn "gh auth refresh -h github.com -s read:packages,write:packages"
elif [ -z "$pkg" ]; then
  need "no ghcr.io/$REPO package yet -- it appears after the first build-and-push run"
elif [ "$pkg" = "public" ]; then
  have "package is public"
else
  # The manifest carries no imagePullSecret, so a private package fails the
  # first deploy with ImagePullBackOff. This bit all three repos in this
  # program.
  need "package is $pkg; make it public or the deploy fails ImagePullBackOff"
  warn "gh api -X PATCH user/packages/container/mcp-cimd -f visibility=public"
  warn "(needs: gh auth refresh -h github.com -s write:packages)"
  warn "or: Package settings -> Danger Zone -> Change visibility -> Public"
fi

# ── Report ───────────────────────────────────────────────────────────────────

echo
if [ "$todo" -eq 0 ]; then
  echo "Everything is set up. Push to main, then ./infra/verify-deploy.sh"
  exit 0
fi
if [ "$APPLY" = yes ]; then
  echo "$todo item(s) still need attention -- see MISSING above."
else
  echo "$todo item(s) missing. Re-run with --apply to set up what can be automated."
fi
exit 1
