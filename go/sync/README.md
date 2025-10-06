## Description

- Project để đồng bộ dữ liệu cve lifecycle lên hệ thống, gồm 2 source vti, nvd, 6 lifecycle:

* Create CVE (vti): CVE được thu thập về hệ thống VTI
* Analysis time (vti): VCS_TI thực hiện phân tích ban đầu
* Approve CVE (vti): Gửi cảnh báo lỗ hổng
* In-depth analysis report (vti): Báo cáo phân tích chuyên sâu
* CVE Received (nvd): <sourceIdentifier> công bố CVE
* CVE CISA KEV Update (nvd): CVE bị khai thác

- Cấu trúc source code, gồm 2 processor:

* vti: Sẽ lấy ra tất cả cve có trong hệ thống, đẩy vào các worker để xử lý. Nếu tham số enable_nvd_queue=true, sẽ đẩy queue lên hệ thống rabbitmq trên server để crawl lifecyce từ nvd.
* nvd: Process này dùng để crawl lifecycle trên nvd theo danh sách cve chỉ định

## Getting started

- Cấu hình cho phép gửi queue lên rabbitmq khi loop qua danh sách cve (nếu cần):

```sh
app:
  enable_nvd_queue: true
.........................
```

- Chỉ chạy cập nhật VTI event

```sh
$ go run main.go --m=vti
```

- Chạy cập nhật nvd, với chỉ định cve

```sh
$ go run main.go --m=nvd --cve=CVE-2024-42072,CVE-2024-42073
```

- Chạy cập nhật threat report

```sh
$ go run main.go --m=report
```

- Chạy cập nhật cve

```sh
$ go run main.go --m=cve
```

- Build linux:

```sh
$ GOOS=linux go build -o sync-data main.go
```
