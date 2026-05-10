// Intentionally misconfigured fixture for `cbx audit --source`.
// Do not copy into real infrastructure.

resource "aws_s3_bucket" "demo" {
  bucket = "cbx-audit-source-demo"
  // No versioning, no SSE, no public-access block — at least one of these
  // produces a tfsec finding (AVD-AWS-0089 / AVD-AWS-0088).
}

resource "aws_security_group" "wide_open" {
  name        = "cbx-audit-source-wide-open"
  description = "Intentionally permissive — fixture only."

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
