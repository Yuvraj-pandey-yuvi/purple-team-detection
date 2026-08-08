variable "canary_users" {
  type = map(string)
  default = {
    bashrc  = "jenkins-deploy-temp"
    storage = "backup-user"
    cron    = "s3-backup-cron"
  }
}

resource "aws_iam_user" "canary" {
  for_each = var.canary_users
  name     = each.value
}

resource "aws_iam_access_key" "canary" {
  for_each = var.canary_users
  user     = aws_iam_user.canary[each.key].name
}

output "canary_access_key_ids" {
  value = { for k, v in aws_iam_access_key.canary : k => v.id }
}

output "canary_secret_access_keys" {
  value     = { for k, v in aws_iam_access_key.canary : k => v.secret }
  sensitive = true
}
