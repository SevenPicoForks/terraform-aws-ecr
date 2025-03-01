output "registry_id" {
  value       = module.context.enabled ? aws_ecr_repository.name[local.image_names[0]].registry_id : ""
  description = "Registry ID"
}

output "repository_name" {
  value       = module.context.enabled ? aws_ecr_repository.name[local.image_names[0]].name : ""
  description = "Name of first repository created"
}

output "repository_url" {
  value       = module.context.enabled ? aws_ecr_repository.name[local.image_names[0]].repository_url : ""
  description = "URL of first repository created"
}

output "repository_arn" {
  value       = module.context.enabled ? aws_ecr_repository.name[local.image_names[0]].arn : ""
  description = "ARN of first repository created"
}

output "repository_url_map" {
  value = local.repository_url_map
  description = "Map of repository names to repository URLs"
}

output "repository_arn_map" {
  value = zipmap(
    values(aws_ecr_repository.name)[*].name,
    values(aws_ecr_repository.name)[*].arn
  )
  description = "Map of repository names to repository ARNs"
}
