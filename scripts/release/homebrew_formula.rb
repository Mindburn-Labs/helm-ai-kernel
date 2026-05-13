#!/usr/bin/env ruby
# frozen_string_literal: true

require "optparse"

ARCHES = {
  "darwin-arm64" => "helm-ai-kernel-darwin-arm64",
  "darwin-amd64" => "helm-ai-kernel-darwin-amd64",
  "linux-arm64" => "helm-ai-kernel-linux-arm64",
  "linux-amd64" => "helm-ai-kernel-linux-amd64"
}.freeze

options = {
  repo: "Mindburn-Labs/helm-ai-kernel",
  checksums: File.expand_path("../../bin/SHA256SUMS.txt", __dir__)
}

OptionParser.new do |opts|
  opts.banner = "Usage: homebrew_formula.rb --version VERSION [--checksums PATH] [--repo OWNER/REPO]"
  opts.on("--version VERSION", "Release version, with or without leading v") { |v| options[:version] = v }
  opts.on("--checksums PATH", "Path to SHA256SUMS.txt from make release-binaries") { |p| options[:checksums] = p }
  opts.on("--repo OWNER/REPO", "GitHub repository path") { |r| options[:repo] = r }
end.parse!

abort "missing --version" if options[:version].to_s.strip.empty?
abort "missing checksum file: #{options[:checksums]}" unless File.file?(options[:checksums])

version = options[:version].sub(/\Av/, "")
tag = "v#{version}"

checksums = {}
File.readlines(options[:checksums], chomp: true).each do |line|
  digest, file = line.split(/\s+/, 2)
  next if digest.to_s.empty? || file.to_s.empty?

  checksums[File.basename(file)] = digest
end

missing = ARCHES.values.reject { |artifact| checksums[artifact]&.match?(/\A[0-9a-f]{64}\z/i) }
abort "missing SHA256 entries for: #{missing.join(", ")}" unless missing.empty?

def asset_url(repo, tag, artifact)
  "https://github.com/#{repo}/releases/download/#{tag}/#{artifact}"
end

puts <<~RUBY
  # frozen_string_literal: true

  class HelmAiKernel < Formula
    desc "Fail-closed execution firewall for AI agents"
    homepage "https://github.com/#{options[:repo]}"
    version "#{version}"
    license "Apache-2.0"

    on_macos do
      if Hardware::CPU.arm?
        url "#{asset_url(options[:repo], tag, ARCHES["darwin-arm64"])}"
        sha256 "#{checksums[ARCHES["darwin-arm64"]]}"
      else
        url "#{asset_url(options[:repo], tag, ARCHES["darwin-amd64"])}"
        sha256 "#{checksums[ARCHES["darwin-amd64"]]}"
      end
    end

    on_linux do
      if Hardware::CPU.arm?
        url "#{asset_url(options[:repo], tag, ARCHES["linux-arm64"])}"
        sha256 "#{checksums[ARCHES["linux-arm64"]]}"
      else
        url "#{asset_url(options[:repo], tag, ARCHES["linux-amd64"])}"
        sha256 "#{checksums[ARCHES["linux-amd64"]]}"
      end
    end

    def install
      binary = Dir["helm-ai-kernel-*"].first || "helm-ai-kernel"
      bin.install binary => "helm-ai-kernel"
    end

    test do
      assert_match version.to_s, shell_output("\#{bin}/helm-ai-kernel version 2>&1")
    end
  end
RUBY
