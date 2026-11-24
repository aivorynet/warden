# Homebrew formula for the tap repo aivorynet/homebrew-tap (Formula/aivory-warden.rb).
# Template: packaging/render-packages.sh fills the placeholders.
class AivoryWarden < Formula
  desc "Rotate access tokens on a schedule and use them without handling them"
  homepage "https://github.com/aivorynet/warden"
  version "{{VERSION}}"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/aivorynet/warden/releases/download/v{{VERSION}}/aivory-warden-aarch64-apple-darwin.tar.gz"
      sha256 "{{SHA256_MACOS_ARM64}}"
    end
    on_intel do
      url "https://github.com/aivorynet/warden/releases/download/v{{VERSION}}/aivory-warden-x86_64-apple-darwin.tar.gz"
      sha256 "{{SHA256_MACOS_X64}}"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/aivorynet/warden/releases/download/v{{VERSION}}/aivory-warden-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "{{SHA256_LINUX_ARM64}}"
    end
    on_intel do
      url "https://github.com/aivorynet/warden/releases/download/v{{VERSION}}/aivory-warden-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "{{SHA256_LINUX_X64}}"
    end
  end

  def install
    bin.install "aivory-warden", "awd"
  end

  service do
    run [opt_bin/"aivory-warden", "daemon"]
    keep_alive true
    log_path var/"log/aivory-warden.log"
    error_log_path var/"log/aivory-warden.log"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/aivory-warden --version")
  end
end
