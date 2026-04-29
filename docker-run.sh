docker run --rm \
  --name autooffensive-builder \
  --env-file workers/.env \
  -e GO_SERVER_ADDR=host.docker.internal:50051 \
  --add-host=host.docker.internal:host-gateway \
  -v /var/run/docker.sock:/var/run/docker.sock \
  autooffensive-builder
