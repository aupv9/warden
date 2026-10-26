FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
ARG TARGETARCH
ARG OPENGREP_VERSION=v1.30.2
ARG OPENGREP_SHA256_amd64=a66aa3278457f02b287b985a45b6762aebcaba5000f2689245fd1ed86d1456c7
ARG OPENGREP_SHA256_arm64=90acea5df4b733083f388d4feeb250ca802f671b33d1f222653d1e571dd2b0d8
RUN set -eu; \
    case "$TARGETARCH" in amd64) asset=opengrep_manylinux_x86; sha="$OPENGREP_SHA256_amd64";; \
                          arm64) asset=opengrep_manylinux_aarch64; sha="$OPENGREP_SHA256_arm64";; \
                          *) echo "unsupported arch $TARGETARCH"; exit 1;; esac; \
    python3 -c "import urllib.request,sys; urllib.request.urlretrieve(sys.argv[1], '/usr/local/bin/opengrep')" \
      "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${asset}"; \
    echo "${sha}  /usr/local/bin/opengrep" | sha256sum -c -; \
    chmod 0555 /usr/local/bin/opengrep
USER 65532:65532
WORKDIR /tmp
ENV HOME=/tmp
ENTRYPOINT []
