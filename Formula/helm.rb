# typed: false
# frozen_string_literal: true

class Helm < Formula
  desc "Deterministic governance kernel for AI tool calls"
  homepage "https://github.com/Mindburn-Labs/helm-oss"
  url "https://github.com/Mindburn-Labs/helm-oss/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "Apache-2.0"

  depends_on "go" => :build

  def install
    cd "core" do
      ldflags = %W[
        -s -w
        -X main.version=#{version}
        -X main.commit=#{Utils.git_head}
        -X main.buildTime=#{time.iso8601}
      ]
      system "go", "build", *std_go_args(ldflags:), "./cmd/helm"
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/helm version 2>&1")
  end
end
