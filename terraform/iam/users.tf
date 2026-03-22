#checkov:skip=CKV_AWS_273:Managing explicit IAM users is the purpose of this access-key rotation module.
resource "aws_iam_user" "this" {
  for_each = var.managed_user_info

  name = each.key
  path = "/"
  tags = merge(
    var.common_tags,
    {
      email = each.value.email
    },
    each.value.user_tags,
  )
}
