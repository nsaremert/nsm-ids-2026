# CICFlowMeter (Java V4) — Docker

CICIDS2017/2018 ile aynı yöntemle hesaplanmış akış öznitelikleri için Java
CICFlowMeter'ı Docker (ubuntu:18.04) içinde derler. Python cicflowmeter portu
bazı öznitelikleri (CWR, subflow'lar, segment-size-avg) sahte hesapladığı için
yayımlanabilir veri setinde Java sürümü kullanılır.

Dockerfile/go/gradle-task, hamelin/cicflowmeter-docker projesinden vendor
edilmiştir (kaynak: https://github.com/hamelin/cicflowmeter-docker, MIT).
İmaj build anında CanadianInstituteForCybersecurity/CICFlowMeter'ı çeker.

Kur:   ./pipeline/setup_cicflowmeter.sh          (docker build -> ids-cfm)
Kullan: ./pipeline/extract_features_cic.sh <pcap> <out.csv>
Çıktı: CICFlowMeter V4 ham CSV (84 öznitelik + identifiers). Kanonik CICIDS2017
       isimlerine çevirme: pipeline/cic_to_cicids.py
