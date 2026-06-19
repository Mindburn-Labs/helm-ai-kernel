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
  checksums: File.expand_path("../../bin/SHA256SUMS.txt", __dir__),
  launchpad_data_checksum: nil,
  console_bundle: nil,
  console_bundle_checksum: nil
}

OptionParser.new do |opts|
  opts.banner = "Usage: homebrew_formula.rb --version VERSION [--checksums PATH] [--repo OWNER/REPO]"
  opts.on("--version VERSION", "Release version, with or without leading v") { |v| options[:version] = v }
  opts.on("--checksums PATH", "Path to SHA256SUMS.txt from make release-binaries") { |p| options[:checksums] = p }
  opts.on("--repo OWNER/REPO", "GitHub repository path") { |r| options[:repo] = r }
  opts.on("--launchpad-data-sha256 SHA256", "SHA256 for helm-ai-kernel-launchpad-data.tar") { |v| options[:launchpad_data_checksum] = v }
  opts.on("--console-bundle NAME", "Optional Console web bundle release asset name") { |v| options[:console_bundle] = v }
  opts.on("--console-bundle-sha256 SHA256", "SHA256 for optional Console web bundle") { |v| options[:console_bundle_checksum] = v }
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
if options[:launchpad_data_checksum].to_s.empty? || !options[:launchpad_data_checksum].match?(/\A[0-9a-f]{64}\z/i)
  abort "missing --launchpad-data-sha256"
end
if options[:console_bundle].to_s.empty? != options[:console_bundle_checksum].to_s.empty?
  abort "--console-bundle and --console-bundle-sha256 must be provided together"
end
if !options[:console_bundle_checksum].to_s.empty? && !options[:console_bundle_checksum].match?(/\A[0-9a-f]{64}\z/i)
  abort "invalid --console-bundle-sha256"
end

def asset_url(repo, tag, artifact)
  "https://github.com/#{repo}/releases/download/#{tag}/#{artifact}"
end

console_resource = "\n"
console_install = ""
if !options[:console_bundle].to_s.empty?
  console_resource = [
    "",
    '  resource "console-web" do',
    "    url \"#{asset_url(options[:repo], tag, options[:console_bundle])}\"",
    "    sha256 \"#{options[:console_bundle_checksum]}\"",
    "  end",
    ""
  ].join("\n")
  console_install = [
    "",
    '    resource("console-web").stage do',
    '      (pkgshare/"console").install Dir["*"]',
    "    end"
  ].join("\n")
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

  resource "launchpad-data" do
    url "#{asset_url(options[:repo], tag, "helm-ai-kernel-launchpad-data.tar")}"
    sha256 "#{options[:launchpad_data_checksum]}"
  end#{console_resource}
  def install
    binary = Dir["helm-ai-kernel-*"].first || "helm-ai-kernel"
    bin.install binary => "helm-ai-kernel"

    resource("launchpad-data").stage do
      pkgshare.install "registry"
      pkgshare.install "policies"
    end#{console_install}
  end

  test do
    assert_match version.to_s, shell_output("\#{bin}/helm-ai-kernel version 2>&1")
    assert_match "openclaw", shell_output("\#{bin}/helm-ai-kernel launch matrix --json")
    assert_path_exists pkgshare/"console/index.html" if resources.map(&:name).include?("console-web")
  end
end
RUBY
