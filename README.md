## Quick Start:

```
export ANTHROPIC_API_KEY=...
```

```
cd crs
go run ./cmd/local/ https://github.com/libexpat/libexpat
```

## CRS docker image:

```
docker pull ghcr.io/o2lab/crs-local:latest
docker tag ghcr.io/o2lab/crs-local:latest crs-local
docker run -it --rm --privileged crs-local
```

```
./crs-local /crs-workdir/local-test-integration-delta-01/
```
```
./crs-local /crs-workdir/local-test-libxml2-delta-01/
```
```
./crs-local /crs-workdir/local-test-sqlite3-full-01/
```
```
./crs-local /crs-workdir/local-test-tika-delta-01/
```
```
./crs-local /crs-workdir/local-test-zookeeper-delta-01/
```

## Deploy LOCAL CRS:
```
cd crs
./build-local-crs-image.sh
```