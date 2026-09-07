data "aws_iam_policy_document" "account_researcher_trust" {
  statement {
    sid     = "AccountPrincipalsWithIdentityPermission"
    actions = ["sts:AssumeRole", "sts:SetSourceIdentity"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_iam_role" "actor_a" {
  name                 = "${var.name_prefix}-actor-a"
  description          = "Initial lab actor that touches a seed and starts S1-a or S1-b"
  assume_role_policy   = data.aws_iam_policy_document.account_researcher_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "actor_a" {
  statement {
    sid       = "ReadOnlySyntheticSeeds"
    actions   = ["s3:GetObject"]
    resources = [aws_s3_object.data_seed.arn]
  }

  statement {
    sid       = "ReadSecretSeed"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [aws_secretsmanager_secret.honeytoken.arn]
  }

  statement {
    sid       = "DecryptSyntheticDataSeed"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.cloudtrail.arn]
  }

  statement {
    sid       = "AssumePivotB"
    actions   = ["sts:AssumeRole", "sts:SetSourceIdentity"]
    resources = [aws_iam_role.pivot_b.arn]
  }

  statement {
    sid       = "RunScopedGrantExperiment"
    actions   = ["iam:PutRolePolicy", "iam:DeleteRolePolicy"]
    resources = [aws_iam_role.grant_target.arn]
  }
}

resource "aws_iam_role_policy" "actor_a" {
  name   = "${var.name_prefix}-actor-a"
  role   = aws_iam_role.actor_a.id
  policy = data.aws_iam_policy_document.actor_a.json
}

data "aws_iam_policy_document" "pivot_b_trust" {
  statement {
    actions = ["sts:AssumeRole", "sts:SetSourceIdentity"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.actor_a.arn]
    }
  }
}

resource "aws_iam_role" "pivot_b" {
  name                 = "${var.name_prefix}-pivot-b"
  description          = "Second identity in the deterministic AssumeRole chain"
  assume_role_policy   = data.aws_iam_policy_document.pivot_b_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "pivot_b" {
  statement {
    actions   = ["sts:AssumeRole", "sts:SetSourceIdentity"]
    resources = [aws_iam_role.pivot_c.arn]
  }
}

resource "aws_iam_role_policy" "pivot_b" {
  name   = "${var.name_prefix}-pivot-b"
  role   = aws_iam_role.pivot_b.id
  policy = data.aws_iam_policy_document.pivot_b.json
}

data "aws_iam_policy_document" "pivot_c_trust" {
  statement {
    actions = ["sts:AssumeRole", "sts:SetSourceIdentity"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.pivot_b.arn]
    }
  }
}

resource "aws_iam_role" "pivot_c" {
  name                 = "${var.name_prefix}-pivot-c"
  description          = "Terminal identity that reads, writes, copies, and performs the R3 probe"
  assume_role_policy   = data.aws_iam_policy_document.pivot_c_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "pivot_c" {
  statement {
    sid = "ReadSyntheticCriticalData"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetObjectTagging",
      "s3:GetObjectVersionTagging",
    ]
    resources = [
      aws_s3_object.critical.arn,
      aws_s3_object.data_seed.arn,
      "${aws_s3_bucket.experiment["staging"].arn}/*",
    ]
  }

  statement {
    sid = "WriteDerivedSyntheticData"
    actions = [
      "s3:PutObject",
      "s3:PutObjectTagging",
      "s3:DeleteObject",
    ]
    resources = [
      "${aws_s3_bucket.experiment["staging"].arn}/*",
      "${aws_s3_bucket.experiment["egress"].arn}/*",
    ]
  }

  statement {
    sid = "UseResearchDataKey"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.cloudtrail.arn]
  }

  statement {
    sid       = "ManageOnlyLabPersistenceKey"
    actions   = ["iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:ListAccessKeys"]
    resources = [aws_iam_user.persistence.arn]
  }
}

resource "aws_iam_role_policy" "pivot_c" {
  name   = "${var.name_prefix}-pivot-c"
  role   = aws_iam_role.pivot_c.id
  policy = data.aws_iam_policy_document.pivot_c.json
}

resource "aws_iam_role" "grant_target" {
  name                 = "${var.name_prefix}-grant-target"
  description          = "Role with no data permission until S1-b applies an inline policy"
  assume_role_policy   = data.aws_iam_policy_document.account_researcher_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "grant_target_baseline" {
  statement {
    sid       = "DecryptOnlyNoS3Access"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [aws_kms_key.cloudtrail.arn]
  }
}

resource "aws_iam_role_policy" "grant_target_baseline" {
  name   = "${var.name_prefix}-kms-baseline"
  role   = aws_iam_role.grant_target.id
  policy = data.aws_iam_policy_document.grant_target_baseline.json
}

resource "aws_iam_user" "persistence" {
  name          = "${var.name_prefix}-persistence-target"
  force_destroy = true
}

data "aws_iam_policy_document" "persistence_read" {
  statement {
    actions   = ["s3:GetObject"]
    resources = [aws_s3_object.critical.arn]
  }

  statement {
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [aws_kms_key.cloudtrail.arn]
  }
}

resource "aws_iam_user_policy" "persistence_read" {
  name   = "${var.name_prefix}-synthetic-critical-read"
  user   = aws_iam_user.persistence.name
  policy = data.aws_iam_policy_document.persistence_read.json
}

resource "aws_iam_role" "background_bot" {
  name                 = "${var.name_prefix}-background-bot"
  description          = "Normal synthetic workload; intentionally has no access to decoy or classified prefixes"
  assume_role_policy   = data.aws_iam_policy_document.account_researcher_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "background_bot" {
  statement {
    sid = "NormalPrefixOnly"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    resources = [
      "${aws_s3_bucket.experiment["critical"].arn}/normal/*",
      "${aws_s3_bucket.experiment["staging"].arn}/normal/*",
    ]
  }

  statement {
    sid = "UseResearchDataKey"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.cloudtrail.arn]
  }
}

resource "aws_iam_role_policy" "background_bot" {
  name   = "${var.name_prefix}-background-bot"
  role   = aws_iam_role.background_bot.id
  policy = data.aws_iam_policy_document.background_bot.json
}
