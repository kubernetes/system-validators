# System Validators

A set of system-oriented validators for kubeadm preflight checks.

## Creating releases

To prepare a release of this library please follow this guide:
- The main branch should always contain WIP commits planned for the upcoming release.
- Always create a new branch for MAJOR and MINOR releases. This allows backporting changes.
- Release branch names should be in the format `release-MAJOR.MINOR` (without a `v` prefix).
- Only non-breaking bug fixes can be done in a PATCH release.
- New features must not be added in PATCH releases.
- Breaking changes must be added in a MAJOR release.
- Pushing releases requires write access. To obtain that you must be part of
the [`system-validator-maintainers` team](http://git.k8s.io/org/config/kubernetes/sig-cluster-lifecycle/teams.yaml).

For vendoring the new release in kubernetes/kubernetes you can use its `pin-dependency.sh` script.

Example:
```bash
./hack/pin-dependency.sh k8s.io/system-validators <NEW-TAG>
```

And then PR the changes.

## Community, discussion, contribution, and support

Learn how to engage with the Kubernetes community on the [community page](http://kubernetes.io/community/).

You can reach the maintainers of this project at:

- [Slack](https://kubernetes.slack.com/messages/sig-cluster-lifecycle)
- [Mailing List](https://groups.google.com/a/kubernetes.io/g/sig-cluster-lifecycle)

### Code of conduct

Participation in the Kubernetes community is governed by the [Kubernetes Code of Conduct](code-of-conduct.md).
