# Container Arsenal

Maps the methodology's tools to container images so the engine can emit
**containerized runners** — `podman`/`docker run` commands and Kubernetes `Job`
manifests — for the staged steps. This lets an operator run the whole arsenal
(tools nmap can't cover: web, AD, DNS, cloud) reproducibly, without installing
anything, and scale it on a cluster.

The engine **generates** these launch specs; the operator runs them
(`podman run …` / `kubectl apply -f …`) inside an authorized engagement. The
engine executes nothing itself and ships no exploit payloads — same boundary as
the rest of the platform (see `docs/instructions.md`).

Edit this catalog to match your registry/toolbox — it's a starting point.

```yaml
containers:
  runtime: podman          # default; also: docker, kubernetes
  network: host            # podman/docker --network value
  # Toolbox image for any tool without a dedicated image below. Point this at
  # YOUR toolbox (tools preinstalled): a kali image with metapackages,
  # parrotsec/security, or a custom build. Base kali-rolling has no tools.
  default_image: "docker.io/kalilinux/kali-rolling"
  # Dedicated single-tool images (entrypoint == the tool; args pass through).
  images:
    nmap: "docker.io/instrumentisto/nmap"
    nuclei: "docker.io/projectdiscovery/nuclei"
```
