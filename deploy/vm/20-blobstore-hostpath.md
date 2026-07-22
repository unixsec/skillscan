# VM blobstore fix (2026-07-08)

The VM's `~/k8s/30-monolith.yaml` backed `SKILLSCAN_BLOBSTORE_ROOT=/tmp/blobstore`
with a pod-local `emptyDir` - invisible to any other pod. The airlock
(`libs/common/airlock.py`) requires the monolith and the engine-runner to
read/write the *same* blob store (the monolith writes `artifacts/<hash>/pkg.tar`,
engine-runner reads it and writes `findings/<scan_id>/<engine>.json` back,
the monolith reads that). On this single-node k3s VM, the fix is a
`hostPath` volume mounted at the same path in both pods - real MinIO is the
production answer (coding spec §8), out of scope for this dev VM.

Applied directly via `kubectl patch`/`kubectl apply` on the VM rather than
committed as a durable manifest here, since `~/k8s/*.yaml` is VM-local state
(not tracked in this repo) - this file just documents what changed and why,
for whoever next touches that VM.

- `~/k8s/30-monolith.yaml`: `tmp` emptyDir volume kept as-is (unrelated
  internal scratch space); added a second volume `blobstore` (`hostPath`,
  `path: /var/lib/skillscan-blobstore`, `type: DirectoryOrCreate`) mounted at
  `/var/lib/skillscan/blobstore`; `SKILLSCAN_BLOBSTORE_ROOT` env changed from
  `/tmp/blobstore` to `/var/lib/skillscan/blobstore` (matching the path
  `deploy/helm/skillscan/templates/configmap.yaml` already uses).
- New `~/k8s/60-engine-runner.yaml`: mounts the SAME hostPath at the same
  container path, `SKILLSCAN_REDIS_URL` pointed at the existing `redis`
  service, no DB/Vault env vars at all (INV-10).
- Whatever was in the old `/tmp/blobstore` emptyDir (scratch scan artifacts
  from prior dev/test runs) is lost on this change - low-stakes here, same
  posture as the project's own MySQL data volume already being an emptyDir.
