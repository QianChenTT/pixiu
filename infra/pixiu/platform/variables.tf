# The image the node runs, as a digest. CI passes the digest image-push just produced. A tag
# is refused here, so what runs is always the exact bytes that were scanned and attested
variable "image_digest" {
  type        = string
  description = "Digest of the pixiu image to run, sha256:<64 hex>"

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "image_digest must be sha256: followed by 64 lowercase hex characters."
  }
}
