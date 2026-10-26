# GeoServer 2.25.1 AppSec PoC — CodeQL + Trivy

## Kapsam ve mevcut durum

- Kaynak: `https://github.com/geoserver/geoserver`, tag `2.25.1`.
- Kaynak commit: `6193b5a1961a97261e07b2a501c483ba780bffae`.
- Çalışma dalı: `appsec/geoserver-2.25.1`.
- Bu dosyalar gerçek tarama sonucu değildir. GitHub Actions üzerinde çalıştırılana
  kadar başarılı/başarısız GeoServer koşusu ve doğrulanmış bulgu iddiası yoktur.
- GeoServer başlatılmaz; bu PoC'de Maven build veya dağıtım da yapılmaz.

## Tasarım ve araç seçimi

Tek workflow'da birbirinden bağımsız iki tarama ve her ikisini zorunlu kılan
`Security gate` işi vardır. Böylece bir araç başarısız olsa da diğerinin raporu
üretilebilir. Raporlar 30 gün saklanır. Actions commit SHA'larına, Trivy sürümü
`v0.76.1`'e sabitlenmiştir. Sürüm güncellemeleri incelenerek yapılmalıdır.

- **CodeQL:** Java kaynak analizi, `security-extended`, `build-mode: none`.
  Eski projenin tam build zincirini çalıştırmadan ilk kaynak taramasını sağlar.
  Derlemede üretilen kaynak ve çözülemeyen bağımlılıklar doğruluğu etkileyebilir;
  bu, derlemeyle doğrulanmış tam kapsam iddiası değildir. Sonraki aşamada manual
  build ile kapsam karşılaştırılabilir.
- **Trivy:** `src` altındaki bağımlılık tanımlarını, tüm önem seviyelerinde tarar.
  JSON raporu paket envanterini de içerir; SARIF ve CycloneDX aynı rapordan üretilir.
  Bu SBOM kaynak analizinden türetilmiştir, dağıtılan WAR'ın kesin envanteri değildir.
  NVD API anahtarı gerekmez. Veritabanı ve POM çözümleme için ağ erişimi gerekir.

Trivy POM analizi Maven profillerinin, optional/test/provided kapsamlarının ve
belirlenemeyen transitif bağımlılıkların tamamını garanti etmez. Kaynak taraması
opsiyonel modülleri de görebilir; bunların her müşteri kurulumunda bulunduğu
varsayılmaz. Tarama logları, paket listesi ve hedefler insan tarafından incelenir.
Boş envanter ve rapordaki sürümsüz paketler kapıyı durdurur; bu kontrol, rapora hiç
girmemiş bir bağımlılığı tespit edemez. Üretim kullanımı için aktif Maven profilleri
ve gerçek WAR/JAR içeriğiyle ayrıca karşılaştırma gerekir.

## Politika

- Çalışma dalına her push ve bu dala açılan PR'da çalışır.
- Elle başlatılabilir. Pazartesi 07:23 Türkiye saati haftalık tarama planlanır;
  GitHub zamanlanmış işleri geciktirebilir. Schedule ve UI'da elle başlatma için
  workflow varsayılan dalda bulunmalıdır.
- CodeQL: `security-severity >= 7.0` sonuçları durdurur. SARIF `level: warning`
  alanı güvenlik önem seviyesi yerine kullanılmaz.
- Trivy: HIGH/CRITICAL sonuçlar, henüz düzeltme olmasa da durdurur.
- Bilinmeyen açık önem seviyesi, çözümlenemeyen rapor verisi, boş paket envanteri,
  eksik/bozuk rapor, araç/DB/ağ hatası yayına uygun sonuç sayılmaz.
- Tarama komutunun `exit-code 0` olması yalnızca raporun kapıdan önce üretilmesini
  sağlar; `gate.py` gerçek politikayı uygular. `continue-on-error` kullanılmaz.
- İstisna, baseline veya ignore listesi başlangıçta yoktur. Yeşil sonuç elde etmek
  için eşik yükseltilmez, `ignore-unfixed` açılmaz veya kapı atlanmaz.
- Branch rules/ruleset üzerinden `Security gate` zorunlu check yapılmalıdır.
  Workflow'un kırmızı olması tek başına merge/release işlemini engellemez.
- Release/CD tasarımı: onaylı commit -> build/test -> tek sürümlü aday paket ->
  test ortamına aynı paketin kurulumu -> DAST/yetkilendirme/yükseltme testleri ->
  yayın kararı -> imzalı paket + dağıtım SBOM'u -> kontrollü müşteri kurulumu.
  Bu PoC'de bu dağıtım adımları uygulanmaz.

## İlk çalıştırma

1. Case dalını varsayılan dal yap. CodeQL Default setup açıksa kapat;
   bu workflow Advanced setup'tır.
2. Fork'tan gelen diğer workflow'ları bu PoC için çalıştırman gerekmez. Actions
   etkinleştirilirken bunları ayrı ayrı devre dışı bırakabilirsin; dosyalar silinmez.
3. Bu dört dosyayı commit edip kendi case dalına push et.
4. Actions -> **AppSec - CodeQL and Trivy** -> ilgili koşuyu aç.
   Fork için etkinleştirme gerekiyorsa etkinleştirip **Run workflow** kullan.
5. `Security gate` durumunu, tarama işlerini ve artifact'leri incele.
6. Bulgu nedeniyle başarısız koşunun URL'sini, commit'ini, araç sürümünü, tarama
   tarihini ve öne çıkan rapor bulgularını kaydet. Operasyonel hata varsa önce
   düzelt; bunu güvenlik bulgusu nedeniyle engellenmiş koşu diye sunma.
7. Başarılı koşu için gerçek bulguları değerlendirip uygun düzeltmeleri yap.
   2.25.1 üzerinde değişiklik yapılırsa tag'den farkını ve yeni commit'i belgele.
   Kaynak sabit kalmak zorundaysa yalnızca kanıtlı yanlış pozitif veya yetkili,
   süreli risk kabulü ayrıca tasarlanabilir; şu an böyle bir mekanizma yoktur.
   Gerçek koşular oluşmadan başarılı/başarısız run bağlantısı yazılmaz.

Fork PR'larında kısıtlı token nedeniyle Security sekmesine yükleme atlanır;
tarama, artifact yükleme ve yerel rapor politikası yine çalışır. Kodun kendisi
workflow ve gate'i değiştirebildiğinden bu dosyalar için bağımsız inceleme ve dal
koruması gerekir; bu PoC tek başına kötü niyetli katkıya karşı güven sınırı değildir.

## Yerel kontrol

```bash
python3 -B -m unittest discover -s security/tests -v
```

Testler sentetik raporlarla kapının kararını doğrular. GeoServer taraması veya
GitHub Actions başarılı koşusu yerine geçmez. Uygulama kaynak kodunu çalıştırmaz.

## Kaynaklar ve uyarlamalar

- https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-for-compiled-languages
  — Java derlemesiz analizinin kapsamı; bu eski sürüm için ilk PoC'de seçildi.
- https://github.com/github/codeql-action
  — init/analyze/upload-sarif; tarama ve politika kararı ayrıldı.
- https://www.trivy.dev/docs/latest/guide/coverage/language/java/
  — POM/JAR/WAR kapsamı; WAR doğrulaması kapsam sınırı olarak kaydedildi.
- https://github.com/aquasecurity/setup-trivy
  — Sabit sürümde CLI kurulumu; NVD secret ihtiyacı kaldırıldı.
- https://github.com/actions/upload-artifact
  — Başarısız koşularda da rapor saklama.
- Workflow ve Python kapısı bu case için AI yardımıyla oluşturuldu; upstream
  build workflow'ları değiştirilmedi ve güvenlik eşiği ayrı uygulanır.
