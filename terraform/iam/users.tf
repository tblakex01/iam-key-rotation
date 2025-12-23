variable "user_info" {
  description = "Map of AWS IAM usernames, email address tags and custom user tags"
  type = map(object({
    email     = string
    user_tags = map(string)
  }))
  default = {
    "userA" = {
      email = "userA@jennasrunbooks.com"
      user_tags = {}
    }
    "userB" = {
      email = "userB@jennasrunbooks.com"
      user_tags = {
        "AKIASRJ6UGTMV3JU6CU2" = "testkey1"
      }
    }
  }
}


resource "aws_iam_user" "this" {
  for_each = var.user_info
  name     = each.key
  path     = "/"
  tags = merge(
    var.common_tags,
    {
      email = each.value.email
    },
    each.value.user_tags
  )
  # Note: No provisioners needed for infrastructure deployment
  # Users will use self-service scripts distributed separately for password management
}

# Create access keys for test users (needed for testing key rotation enforcement)
resource "aws_iam_access_key" "this" {
  for_each = var.user_info
  user     = aws_iam_user.this[each.key].name

  depends_on = [aws_iam_user.this]
}
