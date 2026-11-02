terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

resource "aws_s3_account_public_access_block" "account" {
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket" "data" {
  bucket = "parapet-demo-data"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "data" {
  depends_on = [aws_s3_bucket_ownership_controls.data, aws_s3_bucket_public_access_block.data]
  bucket     = aws_s3_bucket.data.id
  acl        = "public-read"
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Suspended"
  }
}

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject", "s3:ListBucket"]
        Resource  = ["arn:aws:s3:::parapet-demo-data", "arn:aws:s3:::parapet-demo-data/*"]
      }
    ]
  })
}

resource "aws_iam_account_password_policy" "account" {
  minimum_password_length        = 8
  password_reuse_prevention      = 3
  require_lowercase_characters   = false
  require_uppercase_characters   = false
  require_numbers                = false
  require_symbols                = false
  allow_users_to_change_password = true
}

resource "aws_iam_user" "deploy" {
  name = "deploy"
}

resource "aws_iam_user_policy" "deploy_admin" {
  name = "deploy-admin"
  user = aws_iam_user.deploy.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "ops" {
  name = "ops-wide"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:*", "ec2:*", "iam:PassRole"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "deploy_ops" {
  user       = aws_iam_user.deploy.name
  policy_arn = aws_iam_policy.ops.arn
}

resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "app_ops" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.ops.arn
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
}

resource "aws_default_security_group" "main" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_security_group_ingress_rule" "db_open" {
  security_group_id = aws_security_group.web.id
  from_port         = 5432
  to_port           = 5432
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_instance" "web" {
  ami                         = "ami-0c02fb55956c7d316"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.web.id]
  associate_public_ip_address = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  root_block_device {
    volume_size = 20
    encrypted   = false
  }
}

resource "aws_ebs_volume" "scratch" {
  availability_zone = "us-east-1a"
  size              = 50
  encrypted         = false
}

resource "aws_ebs_encryption_by_default" "account" {
  enabled = false
}

resource "aws_db_subnet_group" "db" {
  name       = "app-db"
  subnet_ids = [aws_subnet.public.id]
}

resource "aws_db_instance" "db" {
  identifier                  = "app-db"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "app"
  manage_master_user_password = true
  db_subnet_group_name        = aws_db_subnet_group.db.name
  vpc_security_group_ids      = [aws_security_group.web.id]
  publicly_accessible         = true
  storage_encrypted           = false
  backup_retention_period     = 0
  deletion_protection         = false
  auto_minor_version_upgrade  = false
  skip_final_snapshot         = true
}

resource "aws_kms_key" "app" {
  description         = "application key"
  enable_key_rotation = false
}

resource "aws_cloudtrail" "main" {
  name                          = "main"
  s3_bucket_name                = aws_s3_bucket.data.id
  is_multi_region_trail         = false
  enable_log_file_validation    = false
  include_global_service_events = true
}

resource "aws_lambda_function" "api" {
  function_name = "api"
  role          = aws_iam_role.app.arn
  handler       = "app.handler"
  runtime       = "python3.8"
  s3_bucket     = aws_s3_bucket.data.id
  s3_key        = "api.zip"
}

resource "aws_lambda_permission" "public" {
  statement_id  = "public"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "*"
}

resource "aws_lambda_function_url" "api" {
  function_name      = aws_lambda_function.api.function_name
  authorization_type = "NONE"
}
