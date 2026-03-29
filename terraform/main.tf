# Intentionally misconfigured for testing purposes
# Checkov should flag these as HIGH/CRITICAL

resource "aws_s3_bucket" "test" {
  bucket = "test-devsecops-bucket"
}

# MISCONFIGURATION: S3 bucket has no versioning enabled
resource "aws_s3_bucket_versioning" "test" {
  bucket = aws_s3_bucket.test.id
  versioning_configuration {
    status = "Disabled"
  }
}

# MISCONFIGURATION: S3 bucket is publicly accessible
resource "aws_s3_bucket_public_access_block" "test" {
  bucket                  = aws_s3_bucket.test.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# MISCONFIGURATION: Security group open to the world on all ports
resource "aws_security_group" "test" {
  name = "test-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
