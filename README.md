## Test LOCAL CRS:
```
export CRS_WORKDIR="/home/zc/afc-crs-all-you-need-is-a-fuzzing-brain/crs_workdir/fwupd_full"
export CRS_WORK_DIR="/home/zc/afc-crs-all-you-need-is-a-fuzzing-brain/crs_workdir/fwupd_full"

echo "CRS_WORKDIR=$CRS_WORKDIR"
echo "CRS_WORK_DIR=$CRS_WORK_DIR"

python3 /home/zc/afc-crs-all-you-need-is-a-fuzzing-brain/crs_workdir/fwupd_full/fuzz-tooling/infra/helper.py build_fuzzers --clean --sanitizer address --engine libfuzzer fwupd /home/zc/afc-crs-all-you-need-is-a-fuzzing-brain/crs_workdir/fwupd_full/afc-fwupd-coverage

cd static-analysis
sudo go run ./cmd/local/main.go /home/zc/afc-crs-all-you-need-is-a-fuzzing-brain/crs_workdir/fwupd_full
sudo CRS_WORK_DIR="/home/zc/afc-crs-all-you-need-is-a-fuzzing-brain/crs_workdir/fwupd_full" go run ./cmd/server

cd ../crs
sudo go run cmd/local/main.go  /home/zc/afc-crs-all-you-need-is-a-fuzzing-brain/crs_workdir/fwupd_delta > tmp 2>&1
```
