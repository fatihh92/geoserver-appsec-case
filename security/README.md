# GeoServer AppSec — CodeQL ve Trivy

## Workflow yapısı

- `.github/workflows/sast-codeql.yml`: SAST - CodeQL, Java kaynak analizi.
- `.github/workflows/sca-trivy.yml`: SCA - Trivy, src altındaki bağımlılık tanımları.
- İki ayrı workflow birbirinden bağımsız çalışır. Ayrı Security gate işi yoktur.
- Düzen, referans repodaki ayrı SAST/SCA işlerine benzer; Semgrep yerine CodeQL kullanılır.
- Eski `appsec.yml` kaldırılmıştır; aynı taramalar iki kez tetiklenmez.

## Modlar

Actions > SAST - CodeQL veya SCA - Trivy > Run workflow > mode:

| Mod | HIGH/CRITICAL bulgu | Teknik hata / geçersiz rapor |
| --- | --- | --- |
| enforce | Başarısız | Başarısız |
| report-only | Başarılı; bulgular raporda kalır | Başarısız |

Push/PR ve haftalık koşular enforce modundadır. Manuel mod seçimi iki workflow için
ayrı yapılır; iki modu karşılaştırırken aynı branch ve commit kullanılmalıdır.
Report-only başarısı açık olmadığı veya yayın onayı verildiği anlamına gelmez.
CodeQL güvenlik kural puanı >=7, Trivy HIGH/CRITICAL enforce modunu durdurur.
Trivy UNKNOWN bulguları report-only modunda orijinal JSON/SARIF raporunda korunur;
enforce modunda inceleme gerektirdiği için başarısızlık oluşturur.
Eksik/bozuk rapor, boş Trivy envanteri ve rapordaki sürümsüz paketler iki modda da başarısızdır.
continue-on-error, baseline, ignore listesi veya açıkları filtreleyerek yeşile çevirme kullanılmaz.

## İlk ve ikinci koşu

1. Bu değişiklikleri commit edip appsec/geoserver-2.25.1 dalına push et.
2. Otomatik iki enforce koşusunu incele. İlk CodeQL raporunda 339 yüksek/kritik
   uyarı kaydı vardı; düzeltilmiş parser ile bulgu kaynaklı başarısızlık beklenir.
   Trivy sonucu yeni koşu tamamlanmadan bilinemez. Teknik hata güvenlik bulgusu sayılmaz.
3. İki workflow için ayrı ayrı Run workflow > aynı branch > report-only seç.
4. Her workflow'un iki moddaki URL, commit SHA, mod ve raporlarını kaydet.
   Sonuçta karşılaştırılacak dört workflow koşusu vardır.
5. Run workflow düğmesi için workflow dosyaları varsayılan dalda bulunmalıdır.
   Haftalık plan da varsayılan dalda çalışır. CodeQL için Advanced setup kullanılır.
6. Eski Security gate zorunlu check'i varsa branch ruleset'ten kaldır;
   push/PR enforce koşularındaki CodeQL SAST ve Trivy SCA kontrollerini seç.
   Manuel report-only koşuları yayın/merge için güvenlik onayı olarak kullanılmamalıdır.

## Raporlar ve teknik düzeltmeler

CodeQL SARIF kuralları hem tool.driver.rules hem tool.extensions altında okunur.
Trivy Maven Central erişimi security/trivy.yaml içindeki mirror üzerinden yapılır;
OSGeo gibi diğer depolar korunur. Mirror erişimi GitHub runner'da doğrulanmalıdır.
Referanstaki offline-scan ve .trivyignore yaklaşımı taşınmadı.

Raporlar her durumda artifact olarak saklanır (30 gün); isimde mod, run ve attempt
bulunur. CodeQL SARIF, Trivy JSON/SARIF ve kaynak analizinden türetilmiş CycloneDX
üretilir. Fork PR'larında Security sekmesine yükleme atlanır; tarama/artifact devam eder.
Tarayıcı sürümleri ve action SHA sabitlemeleri korunmuştur.

## Kapsam sınırları

GeoServer başlatılmaz. CodeQL build-mode:none ile çalışır; üretilmiş kaynak ve
çözülemeyen bağımlılıklar kapsamı etkileyebilir. Trivy POM analizi aktif profillerin
ve optional/test/provided bağımlılıkların tamamını garanti etmez. Kaynak SBOM'u,
dağıtılan WAR'ın kesin envanteri değildir. Eksik bağımlılık uyarıları ayrıca incelenmelidir.

## Yerel doğrulama

python3 -B -m unittest discover -s security/tests -v

Sentetik testler karar mantığını doğrular; gerçek GitHub taraması yerine geçmez.

## Referanslar

- https://github.com/einzigekraft/geoserver-2.25.1-appsec-poc/blob/main/.github/workflows/sca-trivy.yml
- https://github.com/einzigekraft/geoserver-2.25.1-appsec-poc/blob/main/.github/workflows/sast-semgrep.yml
- https://trivy.dev/docs/latest/guide/coverage/language/java/
- https://github.com/github/codeql-action
