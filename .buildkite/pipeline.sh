#!/usr/bin/env bash

BUILDTAGS=""
REGISTRIES="docker.io ghcr.io"
REPOSITORY="authelia/oidc-tester-app"
TAGS=""

CI_MERGE_QUEUE="false"

if [[ ${BUILDKITE_BRANCH} =~ ^gh-readonly-queue/.* ]]; then
  CI_MERGE_QUEUE="true"
  buildkite-agent annotate --style "info" --context "ctx-info" < .buildkite/annotations/merge-queue
fi

if [[ "${BUILDKITE_BRANCH}" =~ ^renovate/ ]]; then
  TAGS="renovate"
elif [[ "${BUILDKITE_BRANCH}" != "master" ]] && [[ ! "${BUILDKITE_BRANCH}" =~ .*:.* ]]; then
  TAGS="${BUILDKITE_BRANCH}"
elif [[ "${BUILDKITE_BRANCH}" != "master" ]] && [[ "${BUILDKITE_BRANCH}" =~ .*:.* ]]; then
  TAGS="PR${BUILDKITE_PULL_REQUEST}"
elif [[ "${BUILDKITE_BRANCH}" == "master" ]] && [[ "${BUILDKITE_PULL_REQUEST}" == "false" ]]; then
  SHORT_SHA=${BUILDKITE_COMMIT:0:7}
  TAGS="latest ${BUILDKITE_COMMIT} master-${SHORT_SHA}"
fi

[[ ${BUILDKITE_BUILD_NUMBER} != "" ]] && TAGS+=" BK${BUILDKITE_BUILD_NUMBER}"

for REGISTRY in ${REGISTRIES}; do for TAG in ${TAGS}; do BUILDTAGS+="-t ${REGISTRY}/${REPOSITORY}:${TAG} "; done; done

cat << EOF
steps:
  - label: ":docker: Build and Deploy"
    command: "docker build ${BUILDTAGS::-1} --label org.opencontainers.image.source=https://github.com/${REPOSITORY} --platform linux/amd64,linux/arm64 --provenance mode=max,reproducible=true --sbom true --builder buildx --progress plain --pull --push ."
EOF
if [[ "${CI_MERGE_QUEUE}" == "true" ]]; then
cat << EOF
    skip: "Skipping CI/CD steps for merge queue build."
EOF
elif [[ "${BUILDKITE_BRANCH}" == "master" ]]; then
cat << EOF
    concurrency: 1
    concurrency_group: "oidc-tester-app-deployments"
EOF
fi
cat << EOF
    agents:
      upload: "fast"
    key: "build-docker-linux"

  - label: ":docker: Update README.md"
    command: "curl \"https://ci.nerv.com.au/readmesync/update?github_repo=${REPOSITORY}&dockerhub_repo=${REPOSITORY}\""
    depends_on:
      - "build-docker-linux"
    agents:
      upload: "fast"
EOF
if [[ "${CI_MERGE_QUEUE}" == "true" ]]; then
cat << EOF
    skip: "Skipping CI/CD steps for merge queue build."
EOF
else
cat << EOF
    if: build.branch == "master"
EOF
fi
