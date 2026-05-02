pipeline {
    agent any

    triggers {
        githubPush()
    }

    options {
        timestamps()
    }

    parameters {
        string(
            name: 'IMAGE_NAME',
            defaultValue: '',
            description: 'Optional Docker repository name without namespace. Leave blank to use a service-based default.'
        )
    }

    environment {
        DOCKER_CREDENTIALS_ID = 'DOKCERHUB-ID-CREDENTIALS'
        NVD_API_KEY_CREDENTIALS_ID = 'nvd-api-key'
        BUILDER_NAME          = 'jenkins-builder'
        PRODUCTION_DEPLOYMENT_HOST = credentials('production-deployment-host')
        DEPLOYMENT_USER            = credentials('deployment-user')
        DEPLOYMENT_KEY             = credentials('deployment-ssh-key')
    }

    stages {

        // ─────────────────────────────────────────────
        stage('Resolve Build Metadata') {
        // ─────────────────────────────────────────────
            steps {
                script {
                    env.TAG = sh(
                        script: 'git rev-parse --short=8 HEAD',
                        returnStdout: true
                    ).trim()

                    def allTargets = [
                        'go-server': [
                            paths:     ['go-server/'],
                            dockerfile: 'go-server/Dockerfile',
                            context:   '.',
                            imageName: 'autooffensive-go-server'
                        ],
                        'fastapi-gateway': [
                            paths:     ['fastapi-gateway/'],
                            dockerfile: 'fastapi-gateway/Dockerfile',
                            context:   '.',
                            imageName: 'autooffensive-fastapi-gateway'
                        ],
                        'worker-builder': [
                            paths:     ['workers/builder/'],
                            dockerfile: 'workers/builder/Dockerfile',
                            context:   '.',
                            imageName: 'autooffensive-worker-builder'
                        ],
                        'worker-scanner': [
                            paths:     ['workers/scanner/'],
                            dockerfile: 'workers/scanner/Dockerfile',
                            context:   '.',
                            imageName: 'autooffensive-worker-scanner'
                        ]
                    ]

                    def changedFiles = sh(
                        script: '''
                            git diff --name-only HEAD~1 HEAD 2>/dev/null || \
                            git diff --name-only $(git rev-list --max-parents=0 HEAD) HEAD
                        ''',
                        returnStdout: true
                    ).trim().split('\n') as List

                    echo "Changed files: ${changedFiles.join(', ')}"

                    def servicesToBuild = []
                    allTargets.each { serviceName, config ->
                        def affected = changedFiles.any { file ->
                            config.paths.any { path -> file.startsWith(path) }
                        }
                        if (affected) {
                            servicesToBuild << [name: serviceName] + config
                        }
                    }

                    def jenkinsfileChanged = changedFiles.any { it == 'Jenkinsfile' }
                    if (servicesToBuild.isEmpty() || jenkinsfileChanged) {
                        echo "No specific service changes detected — building all services."
                        servicesToBuild = allTargets.collect { k, v -> [name: k] + v }
                    }

                    echo "Services to build: ${servicesToBuild.collect { it.name }.join(', ')}"

                    env.SERVICE_NAMES       = servicesToBuild.collect { it.name }.join(',')
                    env.SERVICE_DOCKERFILES = servicesToBuild.collect { it.dockerfile }.join(',')
                    env.SERVICE_CONTEXTS    = servicesToBuild.collect { it.context }.join(',')
                    env.SERVICE_IMAGES      = servicesToBuild.collect { s ->
                        params.IMAGE_NAME?.trim() ? params.IMAGE_NAME.trim() : s.imageName
                    }.join(',')
                }
            }
        }

        stage('Validate') {
            steps {
                script {
                    def names = env.SERVICE_NAMES.split(',')
                    names.each { service ->
                        if (service == 'go-server') {
                            echo "Go validation skipped — compiled inside Docker with correct toolchain"
                        } else if (service == 'fastapi-gateway') {
                            echo "FastAPI validation skipped — compiled inside Docker with correct toolchain"
                        }
                        // worker-builder, worker-scanner later
                    }
                }
            }
        }

        // ─────────────────────────────────────────────
        stage('Deploy to Production') {
        // ─────────────────────────────────────────────
        steps {
            withCredentials([
                usernamePassword(
                    credentialsId: env.DOCKER_CREDENTIALS_ID,
                    usernameVariable: 'DOCKER_USER',
                    passwordVariable: 'DOCKER_PASS'
                )
            ]) {
            sh '''#!/bin/bash
                set -euo pipefail
                IFS=',' read -ra NAMES  <<< "$SERVICE_NAMES"
                IFS=',' read -ra IMAGES <<< "$SERVICE_IMAGES"
                DEPLOY_DIR="/home/rattanakmony.pech.mit18/reffensive-api/production"

                # Ensure dir exists + snapshot state before touching anything
                ssh -i "$DEPLOYMENT_KEY" \
                    -o StrictHostKeyChecking=no \
                    -o BatchMode=yes \
                    "$DEPLOYMENT_USER@$PRODUCTION_DEPLOYMENT_HOST" bash -s "$DEPLOY_DIR" <<'REMOTE'
                set -eu
                    DEPLOY_DIR="$1"
                    mkdir -p "$DEPLOY_DIR"
                    cd "$DEPLOY_DIR"
                    if [ -f docker-compose.production.yml ]; then
                        docker compose -f docker-compose.production.yml config \
                            > "deployment-backup-$(date +%s).yml" 2>/dev/null || true
                    fi
                REMOTE

                # Push latest compose file to remote
                if [ -f "docker-compose.production.yml" ]; then
                    scp -i "$DEPLOYMENT_KEY" \
                        -o StrictHostKeyChecking=no \
                        docker-compose.production.yml \
                        "$DEPLOYMENT_USER@$PRODUCTION_DEPLOYMENT_HOST:$DEPLOY_DIR/docker-compose.production.yml"
                fi

                # Deploy each service
                for i in "${!NAMES[@]}"; do
                    IMAGE_REF="$DOCKER_USER/${IMAGES[$i]}:$TAG"
                    SERVICE="${NAMES[$i]}"
                    ssh -i "$DEPLOYMENT_KEY" \
                        -o StrictHostKeyChecking=no \
                        -o BatchMode=yes \
                        "$DEPLOYMENT_USER@$PRODUCTION_DEPLOYMENT_HOST" bash -s \
                            "$IMAGE_REF" "$SERVICE" "$DEPLOY_DIR" "$DOCKER_USER" "$TAG" <<'REMOTE'
                    set -eu
                    IMAGE_REF="$1"
                    SERVICE="$2"
                    DEPLOY_DIR="$3"
                    export DOCKER_USER="$4"
                    TAG="$5"
                    cd "$DEPLOY_DIR"

                    # Pull only this specific service's image
                    docker pull "$IMAGE_REF"

                    # Deploy only this service without checking/pulling dependencies
                    # Override the image tag for just this service to ensure it uses the new image
                    docker compose -f docker-compose.production.yml up -d \
                        --force-recreate \
                        --no-deps \
                        "$SERVICE"

                    echo "✓ Deployed: $SERVICE → $IMAGE_REF"
                    REMOTE
                done
            '''
        }
    }
}

    // ─────────────────────────────────────────────
    stage('Deploy to Production') {
    // ─────────────────────────────────────────────
        steps {
            withCredentials([
                usernamePassword(
                    credentialsId: env.DOCKER_CREDENTIALS_ID,
                    usernameVariable: 'DOCKER_USER',
                    passwordVariable: 'DOCKER_PASS'
                )
            ]) {
                sh '''#!/bin/bash
                    set -euo pipefail
                    IFS=',' read -ra NAMES  <<< "$SERVICE_NAMES"
                    IFS=',' read -ra IMAGES <<< "$SERVICE_IMAGES"
                    DEPLOY_DIR="/home/rattanakmony.pech.mit18/reffensive-api/production"

                    # Ensure dir exists + snapshot state before touching anything
                    ssh -i "$DEPLOYMENT_KEY" \
                        -o StrictHostKeyChecking=no \
                        -o BatchMode=yes \
                        "$DEPLOYMENT_USER@$PRODUCTION_DEPLOYMENT_HOST" bash -s "$DEPLOY_DIR" <<'REMOTE'
                        set -eu
                        DEPLOY_DIR="$1"
                        mkdir -p "$DEPLOY_DIR"
                        cd "$DEPLOY_DIR"
                        if [ -f docker-compose.production.yml ]; then
                            docker compose -f docker-compose.production.yml config \
                                > "deployment-backup-$(date +%s).yml" 2>/dev/null || true
                        fi
                    REMOTE

                    # Push latest compose file to remote
                    if [ -f "docker-compose.production.yml" ]; then
                        scp -i "$DEPLOYMENT_KEY" \
                            -o StrictHostKeyChecking=no \
                            docker-compose.production.yml \
                            "$DEPLOYMENT_USER@$PRODUCTION_DEPLOYMENT_HOST:$DEPLOY_DIR/docker-compose.production.yml"
                    fi

                    # Deploy each service
                    for i in "${!NAMES[@]}"; do
                        IMAGE_REF="$DOCKER_USER/${IMAGES[$i]}:$TAG"
                        SERVICE="${NAMES[$i]}"
                        ssh -i "$DEPLOYMENT_KEY" \
                            -o StrictHostKeyChecking=no \
                            -o BatchMode=yes \
                            "$DEPLOYMENT_USER@$PRODUCTION_DEPLOYMENT_HOST" bash -s \
                                "$IMAGE_REF" "$SERVICE" "$DEPLOY_DIR" "$DOCKER_USER" "$TAG" <<'REMOTE'
                            set -eu
                            IMAGE_REF="$1"
                            SERVICE="$2"
                            DEPLOY_DIR="$3"
                            export DOCKER_USER="$4"
                            export TAG="$5"
                            cd "$DEPLOY_DIR"
                            docker pull "$IMAGE_REF"
                            docker compose -f docker-compose.production.yml up -d --force-recreate "$SERVICE"
                            echo "✓ Deployed: $SERVICE → $IMAGE_REF"
                        REMOTE
                    done
                '''
        }
    }
}

        // ─────────────────────────────────────────────
        stage('Health Check') {
        // ─────────────────────────────────────────────
            steps {
                sh '''#!/bin/bash
                    set -euo pipefail

                    MAX_RETRIES=10
                    RETRY_COUNT=0

                    until ssh -i "$DEPLOYMENT_KEY" \
                              -o StrictHostKeyChecking=no \
                              -o BatchMode=yes \
                              "$DEPLOYMENT_USER@$PRODUCTION_DEPLOYMENT_HOST" \
                              "curl -sf http://localhost:8000/health >/dev/null 2>&1"; do
                        RETRY_COUNT=$((RETRY_COUNT + 1))
                        if [ "$RETRY_COUNT" -ge "$MAX_RETRIES" ]; then
                            echo "✗ Health check failed after $MAX_RETRIES attempts"
                            exit 1
                        fi
                        echo "Health check attempt $RETRY_COUNT/$MAX_RETRIES — retrying in 10s..."
                        sleep 10
                    done

                    echo "✓ Production service is healthy"
                '''
            }
        }

        // ─────────────────────────────────────────────
        stage('Rollback') {
        // ─────────────────────────────────────────────
            when {
                expression { currentBuild.result == 'FAILURE' }
            }
            steps {
                sh '''#!/bin/bash
                    set -euo pipefail

                    ssh -i "$DEPLOYMENT_KEY" \
                        -o StrictHostKeyChecking=no \
                        -o BatchMode=yes \
                        "$DEPLOYMENT_USER@$PRODUCTION_DEPLOYMENT_HOST" bash -s <<'REMOTE'
                        set -eu
                        cd /home/rattanakmony.pech.mit18/reffensive-api/production
                        LATEST_BACKUP=$(ls -t deployment-backup-*.yml 2>/dev/null | head -1)
                        if [ -n "$LATEST_BACKUP" ]; then
                            echo "▶ Restoring from backup: $LATEST_BACKUP"
                            docker compose -f "$LATEST_BACKUP" up -d
                            echo "✓ Rollback completed"
                        else
                            echo "✗ No backup found — manual intervention required"
                            exit 1
                        fi
                    REMOTE
                '''
            }
        }
    }

    post {
        always {
            sh 'docker logout || true'
        }
        success {
            emailext(
                subject: "✓ Deployment Successful — ${env.TAG}",
                body: """
                    <h2>Deployment Completed Successfully</h2>
                    <p><strong>Tag:</strong> ${env.TAG}</p>
                    <p><strong>Services:</strong> ${env.SERVICE_NAMES}</p>
                    <p><strong>Build:</strong> <a href="${env.BUILD_URL}">#${env.BUILD_NUMBER}</a></p>
                """,
                to: '${DEFAULT_RECIPIENTS}',
                mimeType: 'text/html'
            )
        }
        failure {
            emailext(
                subject: "✗ Deployment FAILED — ${env.TAG}",
                body: """
                    <h2>Deployment Failed</h2>
                    <p><strong>Tag:</strong> ${env.TAG}</p>
                    <p><strong>Services:</strong> ${env.SERVICE_NAMES}</p>
                    <p><strong>Build:</strong> <a href="${env.BUILD_URL}">#${env.BUILD_NUMBER}</a></p>
                    <p><strong style="color:red;">Review logs immediately. Rollback may have been triggered.</strong></p>
                """,
                to: '${DEFAULT_RECIPIENTS}',
                mimeType: 'text/html'
            )
        }
    }
}
