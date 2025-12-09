docker build -t edge-nids-v1 .
docker run --rm \
    --name my-router \
    --cpus="0.5" \
    --memory="512m" \
    edge-nids-v1