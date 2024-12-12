FROM opensuse/leap:15.6 AS repos

RUN --mount=type=cache,id=zypp,target=/var/cache/zypp \
	sed -i -E 's/https?:\/\/download.opensuse.org/https:\/\/mirror.firstyear.id.au/g' /etc/zypp/repos.d/*.repo && \
	zypper mr -d -f repo-openh264 && \
	zypper -v ref --force && \
	zypper -v dup -y

FROM repos AS builder

RUN --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper --non-interactive in cargo

COPY . /usr/src/libkrimes

WORKDIR /usr/src/libkrimes

RUN cargo build --release

RUN --mount=type=cache,id=cargo,target=/cargo \
    export CARGO_HOME=/cargo && \
    cargo build \
        --target-dir="/usr/src/libkrimes/target/" \
        --release

FROM repos

COPY --from=builder /usr/src/libkrimes/target/release/krimedc /sbin/

EXPOSE 88/tcp
EXPOSE 88/udp

CMD [ "/sbin/krimedc", "run", "/data/krime.conf"]

