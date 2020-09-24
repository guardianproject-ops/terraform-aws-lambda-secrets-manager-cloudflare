variable "secret_prefix" {
  type        = string
  description = "The Secrets Manager Secret prefix of the secrets this lambda will manage, including the wild card if you want one. e.g., 'cloudflare/*'"
}

variable "api_token" {
  type        = string
  default     = ""
  description = "A Cloudflare API token with User.API Tokens permission"
}
variable "api_key" {
  type        = string
  default     = ""
  description = "The cloudflare user's Global API Key"
}
variable "api_email" {
  type        = string
  default     = ""
  description = "The cloudflare user's email address"
}
variable "api_origin_key" {
  type        = string
  default     = ""
  description = "The Origin CA Key to generate certificates"
}
variable "api_tunnel_service_key" {
  type        = string
  default     = ""
  description = "A single argo tunnel service key to use to generate argo tunnel tokens"
}

variable "api_tunnel_service_key_arns" {
  type        = list(string)
  default     = []
  description = "A list of AWS SM Secrets containing argo tunnel service keys that this lambda could use to generate argo tunnel tokens"
}

variable "build_number" {
  type        = string
  description = "Any time this value changes, the lambda will be rebuilt from source. The value it self has no meaning."
  default     = "0"
}

variable "cloudwatch_log_group_arn" {
  type        = string
  description = "The ARN of the cloudwatch log group this lambda will log to"
}

variable "create_cloudwatch_log_metric" {
  type        = bool
  default     = true
  description = "Whether to create cloudwatch metric for failed rotations"
}


variable "cloudtrail_log_group_name" {
  type        = string
  description = "The ARN of the log group cloudtrail events are sent to ( used when creating cloudwatch log metric )"
  default     = ""
}

variable "cloudwatch_metric_name" {
  type        = string
  default     = "FailedRotations"
  description = "The name of the cloudwatch metric"
}

variable "cloudwatch_metric_namespace" {
  type        = string
  default     = "SecretsManager"
  description = "The namespace to place the metric in"
}
