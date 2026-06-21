cross_engine := `command -v podman >/dev/null 2>&1 && echo podman || echo docker`
dist_dir := "dist"

export CROSS_CONTAINER_ENGINE := cross_engine

default:
    @just --list

[group('build')]
build-static:
    cargo build --release --target x86_64-unknown-linux-musl
    mkdir -p {{ dist_dir }}
    cp target/x86_64-unknown-linux-musl/release/udpcp {{ dist_dir }}/udpcp-linux-x86_64

[group('build')]
build-rpi:
    cross build --release --target aarch64-unknown-linux-musl
    mkdir -p {{ dist_dir }}
    cp target/aarch64-unknown-linux-musl/release/udpcp {{ dist_dir }}/udpcp-linux-aarch64

[group('build')]
dist: build-static build-rpi

[group('package')]
deb-amd64: build-static
    cargo deb --no-build --no-strip --target x86_64-unknown-linux-musl --output {{ dist_dir }}/

[group('package')]
deb-arm64: build-rpi
    cargo deb --no-build --no-strip --target aarch64-unknown-linux-musl --output {{ dist_dir }}/

[group('package')]
deb: deb-amd64 deb-arm64

clean:
    cargo clean
    rm -rf {{ dist_dir }}
