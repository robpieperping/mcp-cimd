# Deploying mcp-cimd

Target: Ping SE DevOps cluster `ping-dev-aws-us-east-2`, namespace
`ping-devops-robpieper`.

This server is its own protected resource — it validates ChatGPT's token
itself rather than sitting behind PingGateway (plan §3). It is therefore
publicly reachable at `https://mcp-cimd.ping-devops.com`, and its own
token validation is the only thing between the internet and SmileCDR.

The Ingress routes **only** `/mcp` and
`/.well-known/oauth-protected-resource`, not `/`. `/healthz` and
`/readyz` are unauthenticated by design — a kubelet probe must not need
a token, and the kubelet reaches the pod directly — but `/readyz`
reports the FHIR server's base URL, which is not something to hand to
the internet.

## Two scripts do the work

```bash
./infra/k8s/bootstrap.sh            # report what is and is not set up
./infra/k8s/bootstrap.sh --apply    # do the missing one-time pieces
./infra/verify-deploy.sh            # check the deployment, no token needed
./infra/verify-deploy.sh "$TOKEN"   # also drive a real MCP session
```

`bootstrap.sh` is idempotent and is the quickest way to confirm the
setup is still intact. It needs an interactive kubectl session, because
this cluster authenticates through an OIDC exec plugin that opens a
browser. The ServiceAccount token it reads is written only to a mode-600
temp file, verified against the cluster, handed to `gh secret set` over
stdin, and deleted; it is never printed.

The rest of this file is what those scripts automate, for when you need
to do a step by hand or understand what it did.

## Cluster facts worth knowing

- **All nodes are arm64** (Graviton `r7g.xlarge`), verified 2026-09-10.
  CI builds `linux/arm64` for that reason. An amd64 image fails as
  `exec format error` in CrashLoopBackOff, which reads like an app bug.
  Note this contradicts `bxhealth-demo-base/docs/setup-cluster.md`,
  which says the build needs an amd64 host; that doc is wrong.
- Default StorageClass is `gp2`. This service is stateless and claims no
  volume.
- The human kubeconfig authenticates through an **interactive OIDC exec
  plugin**, so it cannot be handed to CI (see below).

## One-time setup

### 1. CI deploy identity

`KUBE_CONFIG_B64` cannot be your own kubeconfig: the exec plugin needs a
browser. CI gets a namespace-scoped ServiceAccount instead.

```bash
kubectl apply -n ping-devops-robpieper -f infra/k8s/ci-rbac.yaml
```

Then build the kubeconfig from the issued token:

```bash
NS=ping-devops-robpieper
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
CA=$(kubectl get secret github-deployer-token -n $NS -o jsonpath='{.data.ca\.crt}')
TOKEN=$(kubectl get secret github-deployer-token -n $NS -o jsonpath='{.data.token}' | base64 -d)

cat > ci-kubeconfig.yaml <<CFG
apiVersion: v1
kind: Config
clusters:
- name: ping-dev-aws-us-east-2
  cluster: { server: ${SERVER}, certificate-authority-data: ${CA} }
contexts:
- name: ci
  context: { cluster: ping-dev-aws-us-east-2, namespace: ${NS}, user: github-deployer }
current-context: ci
users:
- name: github-deployer
  user: { token: ${TOKEN} }
CFG

base64 < ci-kubeconfig.yaml | tr -d '\n' | gh secret set KUBE_CONFIG_B64
gh secret set K8S_NAMESPACE --body "$NS"
rm ci-kubeconfig.yaml
```

Verify it before trusting CI with it:

```bash
KUBECONFIG=ci-kubeconfig.yaml kubectl auth whoami
KUBECONFIG=ci-kubeconfig.yaml kubectl auth can-i patch deployments.apps -n $NS   # yes
KUBECONFIG=ci-kubeconfig.yaml kubectl auth can-i get secrets -n $NS              # no
```

### 2. Application secret

```bash
kubectl create secret generic mcp-cimd-secrets -n ping-devops-robpieper \
  --from-env-file=.env
```

Carries `FHIR_BASE_URL` and, if the upstream FHIR call is to be
authenticated at all, `PINGONE_ENV_ID`, `PINGONE_CLIENT_ID` and
`PINGONE_CLIENT_SECRET`. The FHIR base URL is not secret but lives here
so there is one place to change it. The CI ServiceAccount deliberately
cannot read this secret.

The inbound OAuth settings (`MCP_RESOURCE`, `OAUTH_ISSUER`,
`MCP_TOOLSET`) are **not** here: they are public identifiers and live in
the Deployment's `env` block, where a change shows up in a diff.

### 3. Container image

CI pushes `ghcr.io/robpieperping/mcp-cimd` using the workflow's
own `GITHUB_TOKEN`; no registry secret is needed.

**The package must be public**, because the manifest carries no
`imagePullSecret`. GHCR packages inherit the repository's visibility on
first push, so a package from a private repo starts private and the
first deploy fails with `ImagePullBackOff` until it is flipped:

> Package settings → Danger Zone → Change visibility → Public

To keep it private instead, create a `docker-registry` secret from a PAT
with `read:packages` and add `imagePullSecrets` back to the pod spec.

## Deploy

Push to `main`; the workflow runs `check` → `build-and-push` → `deploy`.
`check` now runs `npm test`, so a regression in token validation fails
the image rather than the deploy.

**Order matters on a fresh repo.** The GHCR package does not exist until
the first `build-and-push`, and it inherits the repository's private
visibility, so the sequence is: push once (the deploy job fails if the
secrets are not set yet), flip the package public, run
`bootstrap.sh --apply`, then re-run the workflow.

```bash
gh workflow run "Build And Deploy (main)"
```

Manually:

```bash
kubectl apply -n ping-devops-robpieper -f infra/k8s/k8s.yaml
kubectl rollout status -n ping-devops-robpieper deploy/mcp-cimd
```

## Verify

`./infra/verify-deploy.sh` is the Phase C exit criterion as a pass/fail
report: DNS, the wildcard certificate and whether it covers the host,
the metadata document and whether the `resource` it advertises matches
the URL actually serving it, the 401 challenge and whether the
`resource_metadata` URL it names resolves, the authorization server's
own discovery document and whether its `issuer` matches exactly, and
that `/healthz` and `/readyz` are *not* internet-reachable.

A stale `MCP_RESOURCE` in the Deployment env is the failure worth
naming: downstream it is a flat 401 with no other clue, so the script
compares the advertised resource against the host it asked.

The authorization server's discovery document defaults to OpenID Connect
Discovery on the issuer our metadata names — on this instance
`https://facile-pastrami-lipogram.ping-devops.com/.well-known/openid-configuration`,
which is the endpoint in use. PF's RFC 8414 path returns 403, and that
is fine: an authorization server need only provide one mechanism, and an
MCP client must support both. Override with `OAUTH_METADATA_URL`, which
also lets the authorization server be checked before this server is
deployed at all:

```bash
OAUTH_METADATA_URL=https://facile-pastrami-lipogram.ping-devops.com/.well-known/openid-configuration \
  ./infra/verify-deploy.sh
```

By port-forward, for the endpoints the Ingress does not expose:

```bash
kubectl port-forward -n ping-devops-robpieper deploy/mcp-cimd 3000:3000

curl -s localhost:3000/healthz
curl -s localhost:3000/readyz    # reports the FHIR server's advertised fhirVersion

# Protected-resource metadata: unauthenticated by design.
curl -s localhost:3000/.well-known/oauth-protected-resource | jq

# And the challenge a client with no token gets. This must carry
# resource_metadata, or ChatGPT has no way to discover PingFederate.
curl -isS -X POST localhost:3000/mcp -H 'content-type: application/json' -d '{}' \
  | grep -i www-authenticate
```

The Inspector needs a token, so point it at the deployed URL once the
Phase C Ingress exists rather than at a port-forward: it drives the whole
OAuth flow, which cannot complete against `localhost`.

## Notes

- **One replica, on purpose.** MCP sessions are held in memory keyed by
  `Mcp-Session-Id`. A second pod answers follow-up requests for sessions
  it never saw, producing intermittent `Session not found` 404s. Scaling
  up needs sticky sessions or a shared session store first.
- Both probes use `/healthz`, which never touches FHIR. `/readyz` does
  call FHIR and is the better-looking readiness probe, but wiring it in
  would evict the pod from the Service whenever FHIR hiccups, turning a
  clear tool error into an opaque 503.
- Teardown: `kubectl delete -f infra/k8s/k8s.yaml`. Per SE DevOps policy
  cleanup is your responsibility; `kubectl scale --replicas=0` is the
  cheap idle state.
