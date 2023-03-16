#!/bin/sh

TARGET="${1:-project1}"
USER=$(id -u)
GROUP=$(id -g)

case "$TARGET" in
"project1")
    ARTIFACTS="prj1-voting-client prj1-voting-server"
    ;;
*) ;;
esac

mkdir -p "./artifacts/${TARGET}"

if ! command -v docker >/dev/null; then
    echo "You should have docker installed!"
    exit 1
fi

if [ "$(docker images -q tc-builder:latest 2>/dev/null)" = "" ]; then
    docker build -t tc-builder .
fi

CMDS='cargo clean --release && cargo --config registries.crates-io.protocol=\"sparse\" build --release'

echo "${CMDS}" | xargs -0 -I %% docker run --rm \
    --user "$USER:$GROUP" \
    -v "$(pwd)":/usr/src/workspace \
    -w "/usr/src/workspace/$TARGET" \
    tc-builder:latest \
    /bin/sh -c "%%"

for b in $ARTIFACTS; do
    cp "./target/release/$b" "./artifacts/$TARGET/"
    strip "./artifacts/$TARGET/$b"
done
