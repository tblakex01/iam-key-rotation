#===================================#
#    ACCESS KEY RECOVERY HTTP API   #
#===================================#

resource "aws_cloudwatch_log_group" "access_key_recovery_api" {
  name              = local.access_key_recovery_api_log_group_name
  retention_in_days = local.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn

  tags = var.common_tags
}

resource "aws_apigatewayv2_api" "access_key_recovery" {
  name          = local.access_key_recovery_api
  protocol_type = "HTTP"
  description   = "Anonymous self-service access-key recovery request API"

  tags = var.common_tags
}

resource "aws_apigatewayv2_integration" "access_key_recovery_request" {
  api_id                 = aws_apigatewayv2_api.access_key_recovery.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.access_key_recovery_request.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
  timeout_milliseconds   = 29000
}

resource "aws_apigatewayv2_route" "access_key_recovery_request" {
  api_id             = aws_apigatewayv2_api.access_key_recovery.id
  route_key          = local.access_key_recovery_route_key
  #checkov:skip=CKV_AWS_309:The recovery route is intentionally anonymous and explicitly sets authorization_type to NONE.
  authorization_type = "NONE"
  target             = "integrations/${aws_apigatewayv2_integration.access_key_recovery_request.id}"
}

resource "aws_apigatewayv2_stage" "access_key_recovery" {
  api_id      = aws_apigatewayv2_api.access_key_recovery.id
  name        = var.access_key_recovery_stage_name
  auto_deploy = true

  default_route_settings {
    detailed_metrics_enabled = true
    throttling_burst_limit   = var.access_key_recovery_api_burst_limit
    throttling_rate_limit    = var.access_key_recovery_api_rate_limit
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.access_key_recovery_api.arn
    format = jsonencode({
      requestId        = "$context.requestId"
      sourceIp         = "$context.identity.sourceIp"
      requestTime      = "$context.requestTime"
      routeKey         = "$context.routeKey"
      status           = "$context.status"
      integrationError = "$context.integrationErrorMessage"
      responseLength   = "$context.responseLength"
      userAgent        = "$context.identity.userAgent"
    })
  }

  tags = var.common_tags
}

resource "aws_lambda_permission" "allow_apigateway_access_key_recovery" {
  statement_id  = "AllowExecutionFromAccessKeyRecoveryApi"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.access_key_recovery_request.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.access_key_recovery.execution_arn}/*/POST/access-key-recovery/request"
}

resource "aws_cloudwatch_metric_alarm" "access_key_recovery_api_4xx" {
  alarm_name          = local.access_key_recovery_api_4xx_alarm_name
  alarm_description   = "Alert when the access-key recovery HTTP API returns 4XX responses."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "4xx"
  namespace           = "AWS/ApiGateway"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alarm_sns_topic]

  dimensions = {
    ApiId = aws_apigatewayv2_api.access_key_recovery.id
    Stage = aws_apigatewayv2_stage.access_key_recovery.name
  }

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "access_key_recovery_api_5xx" {
  alarm_name          = local.access_key_recovery_api_5xx_alarm_name
  alarm_description   = "Alert when the access-key recovery HTTP API returns 5XX responses."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "5xx"
  namespace           = "AWS/ApiGateway"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alarm_sns_topic]

  dimensions = {
    ApiId = aws_apigatewayv2_api.access_key_recovery.id
    Stage = aws_apigatewayv2_stage.access_key_recovery.name
  }

  tags = var.common_tags
}
