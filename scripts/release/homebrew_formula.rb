# frozen_string_literal: true

# Homebrew formula for HELM — Execution Authority for AI Agents
# Install: brew install mindburn-labs/tap/helm
#
# To update after a release:
#   1. Update `url` and `sha256` for each platform
#   2. Submit to mindburn-labs/homebrew-tap

class Helm < Formula
  desc "Execution Authority for AI agents — governed tool execution with cryptographic receipts"
  homepage "https://github.com/Mindburn-Labs/helm-oss"
  version "0.9.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Mindburn-Labs/helm-oss/releases/download/v#{version}/helm-darwin-arm64"
      sha256 "PLACEHOLDER_SHA256_DARWIN_ARM64"
    else
      url "https://github.com/Mindburn-Labs/helm-oss/releases/download/v#{version}/helm-darwin-amd64"
      sha256 "PLACEHOLDER_SHA256_DARWIN_AMD64"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Mindburn-Labs/helm-oss/releases/download/v#{version}/helm-linux-arm64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/Mindburn-Labs/helm-oss/releases/download/v#{version}/helm-linux-amd64"
      sha256 "PLACEHOLDER_SHA256_LINUX_AMD64"
    end
  end

  def install
    binary = Dir["helm-*"].first || "helm"
    bin.install binary => "helm"
  end

  test do
    assert_match "HELM Kernel", shell_output("#{bin}/helm --help")
    assert_match "onboard", shell_output("#{bin}/helm --help")
  end
end
