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

variable "hostname" {
  type = string
}
variable "zone_id" {
  type = string
}
variable "valid_days" {
  type    = number
  default = 7
}

variable "cloudtrail_log_group_name" {
  type = string
}
