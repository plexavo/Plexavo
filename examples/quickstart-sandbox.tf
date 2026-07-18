# Plexavo quickstart sandbox
#
# One deliberately-public, deliberately-empty S3 bucket, so you can see
# what a real finding looks like on your very first run — without
# pointing the scanner at real infrastructure before you trust it.
#
# Cost: effectively zero. An empty S3 bucket with no requests against it
# costs nothing meaningful. Destroy it when you're done (see below) —
# there's no reason to leave a deliberately-insecure bucket sitting in a
# real AWS account longer than it takes to try the tool once.
#
# DO NOT put real data in this bucket. It is intentionally misconfigured
# — that's the entire point — and anything you upload to it is genuinely
# publicly readable the moment you `terraform apply`.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  # Uses the same local credentials/profile you'd pass to `plexavo scan`.
  # Set AWS_PROFILE, or pass -var-file, or edit this directly — whatever
  # matches how you normally authenticate to AWS.
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "quickstart_sandbox" {
  bucket = "plexavo-quickstart-sandbox-${random_id.suffix.hex}"

  tags = {
    Purpose = "plexavo-quickstart-sandbox"
    Note    = "Deliberately public. Safe to destroy at any time. Do not store real data here."
  }
}

# STOR-19: Block Public Access left off. This is the single most common
# real-world S3 misconfiguration this scanner detects — every setting
# below defaults to blocking public access; this sandbox turns all four
# off so the check has something to find.
resource "aws_s3_bucket_public_access_block" "quickstart_sandbox" {
  bucket = aws_s3_bucket.quickstart_sandbox.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# STOR-20: a bucket policy granting Principal:* — anyone, unauthenticated,
# can read anything in this bucket. Depends on the public access block
# above being disabled first, or AWS rejects the policy outright.
resource "aws_s3_bucket_policy" "quickstart_sandbox" {
  bucket     = aws_s3_bucket.quickstart_sandbox.id
  depends_on = [aws_s3_bucket_public_access_block.quickstart_sandbox]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadForQuickstartDemo"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.quickstart_sandbox.arn}/*"
    }]
  })
}

output "bucket_name" {
  value       = aws_s3_bucket.quickstart_sandbox.id
  description = "Pass this account to `plexavo scan` — no special setup needed, it's the same account this bucket was created in."
}

# ---------------------------------------------------------------------------
# Usage:
#
#   cd examples
#   terraform init
#   terraform apply
#   plexavo scan --profile <your-profile> --report-html report.html
#
# You should see at least one STOR-19 and one STOR-20 finding pointing at
# this bucket. When you're done looking at the report:
#
#   terraform destroy
# ---------------------------------------------------------------------------
