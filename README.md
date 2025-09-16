# CRS Deployment

> ⚠️ **Branch Information**  
> This branch contains the **identical CRS version** used for the **aixcc final round**.  
> For a local or single-VM test version, please switch to the **[`jeff`](../../tree/jeff)** branch.

---

## CRS AKS DEPLOY:
```
./deploy-docker-images.sh
cd aks-cluster-deploy
make up
```

## CRS LOCAL TEST:
```
cd crs
LOCAL_TEST=1 go run ./cmd/server/main.go
```

#### COMPETITION_API:
```
competition-api
go run ./cmd/server/main.go
```

## Testing
Go to `path/to/generate-challenge-task`

Test full-scan:
```
./generate-challenge-task.sh -c http://localhost:7080 -t "https://github.com/aixcc-finals/example-libpng" -b 2c894c66108f0724331a9e5b4826e351bf2d094 -x
```
Test delta-scan:
```
./generate-challenge-task.sh -c http://localhost:7080 -t "https://github.com/aixcc-finals/example-libpng" -b 0cc367aaeaac3f888f255cee5d394968996f736e -r 2c894c66108f0724331a9e5b4826e351bf2d094b -x
```

### curl scripts

full-scan:
```
curl -s -X POST "http://localhost:8080/v1/task/" -H "Content-Type: application/json"         --user "api_key_id":"api_key_token" -d '{"message_id":"7281a673-6358-4eca-8ea0-ffaacc707c39","message_time":1736875979000,"tasks":[{"task_id":"c7393d78-cc0b-435a-8c7d-d4191a28f65c","type":"full","deadline":1736890379000,"source":[{"type":"repo","url":"https://aixcctfstate123.blob.core.windows.net/tfstate/f13a57efa5b068a2ff3ccae607464facd157e56aa81a252c99dab083ec810113.tar.gz?se=2025-01-14T21%3A32%3A57Z&sp=r&sv=2022-11-02&sr=b&sig=KtiEV2LuIedBSznkSZO6GVp3dFvDh%2BLq4OneBzE97Tg%3D","sha256":"f13a57efa5b068a2ff3ccae607464facd157e56aa81a252c99dab083ec810113"},{"type":"fuzz-tooling","url":"https://aixcctfstate123.blob.core.windows.net/tfstate/201eea48d1767e92f7cc80926676096372b1b0af44ee06dedc1691e94dc102db.tar.gz?se=2025-01-14T21%3A32%3A59Z&sp=r&sv=2022-11-02&sr=b&sig=LR%2FP8PIQvo1BC1nVCMrZvIiB3FwOCR5hIp58Tn71J1Y%3D","sha256":"201eea48d1767e92f7cc80926676096372b1b0af44ee06dedc1691e94dc102db"}]}]}'
```

delta-scan:
```
curl -s -X POST "http://localhost:8080/v1/task/" -H "Content-Type: application/json"         --user "api_key_id":"api_key_token" -d '{"message_id":"0d2ab7cd-766c-49f2-86f6-926fbdb96546","message_time":1736889189000,"tasks":[{"task_id":"42910c67-5aa6-4b36-b3d8-d2af94915784","type":"delta","deadline":1736903589000,"source":[{"type":"repo","url":"https://aixcctfstate123.blob.core.windows.net/tfstate/6506009e5f2cbfbc876c93f3ea9536812a16aa7dbb0326c6e86dcca891347840.tar.gz?se=2025-01-15T01%3A13%3A06Z&sp=r&sv=2022-11-02&sr=b&sig=GF3HvYKMrjd2s%2F%2B2gz8JxQP7J7UGG0mDG7NrCApN2E8%3D","sha256":"6506009e5f2cbfbc876c93f3ea9536812a16aa7dbb0326c6e86dcca891347840"},{"type":"fuzz-tooling","url":"https://aixcctfstate123.blob.core.windows.net/tfstate/b2eb56760411cd47bca531bb914769fc9545244041d85e7cb6af14c7f074e9ca.tar.gz?se=2025-01-15T01%3A13%3A08Z&sp=r&sv=2022-11-02&sr=b&sig=C3jwhDwK%2Bl%2BSlk%2BTWIHp3%2Bvf8byi6IacXKIB85%2Bvfko%3D","sha256":"b2eb56760411cd47bca531bb914769fc9545244041d85e7cb6af14c7f074e9ca"},{"type":"diff","url":"https://aixcctfstate123.blob.core.windows.net/tfstate/8f30a73bee0d410fe2b3046e2a108f2790888d125e0eb80f0eacf2bf4d9e4273.tar.gz?se=2025-01-15T01%3A13%3A05Z&sp=r&sv=2022-11-02&sr=b&sig=W4QoREUh63aa7yVyZwJpEJantp8oO0nkyjB74rJulWk%3D","sha256":"8f30a73bee0d410fe2b3046e2a108f2790888d125e0eb80f0eacf2bf4d9e4273"}]}]}'
```

# Dataset
We’ve gone ahead and uploaded the datasets to Hugging Face. You can now find them here:

C Challenges: https://huggingface.co/datasets/Kitxuuu/AIXCC-C-Challenge

Java Challenges: https://huggingface.co/datasets/Kitxuuu/AIXCC-Java-Challenge

We’ve also submitted our paper to Hugging Face Papers, which is available at: https://huggingface.co/papers/2509.07225
