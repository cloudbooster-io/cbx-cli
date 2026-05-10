# helm-sample-source

Minimal Helm chart consumed by `e2e/audit_test.go` to exercise
`cbx audit --source` against the Helm flavor. Contains intentionally
misconfigured workloads in `templates/`; **do not** install in real
clusters.
