# 📘 Proje Rehberi — MiniFirewall Lab'i Baştan Sona Anlamak

Bu dosya sana projeyi **sıfırdan anlatan** bir öğrenme notu. README teknik referans, SUNUM_AKISI.md sunum provası — bu dosya ise "bu proje ne, neden böyle yazıldı, içi nasıl işliyor" sorularının cevabı. Sırayla oku, atlama yapma; her bölüm bir öncekinin üzerine inşa ediyor.

---

## 1. Bu proje nedir?

**MiniFirewall Lab**, bir **güvenlik duvarının (firewall) karar verme mantığını** gerçek ağ donanımına dokunmadan, tamamen yazılım olarak simüle eden bir Python projesi.

Somut olarak ne yapıyor: Sana **sahte ağ paketleri** üretiyor (gerçek bir bilgisayardan gelmiş gibi, ama aslında sadece bir Python nesnesi — kaynak IP, hedef IP, protokol, port, TCP bayrakları içeren 5-6 alanlık bir veri yapısı), bu paketleri **senin yazdığın kurallardan** geçiriyor ve her biri için "ALLOW" (geçsin) veya "DENY" (engelle) kararı veriyor — tıpkı gerçek bir firewall'un (ör. iptables, pfSense, bir kurumsal Cisco ASA cihazı) yaptığı gibi.

**Neden "simülasyon"?** Çünkü gerçek bir firewall işletim sisteminin ağ kartına (network interface) bağlanır, gerçek elektrik sinyallerinden gelen paketleri yakalar. Biz böyle bir şey yapmıyoruz — işletim seviyesine inmek hem çok karmaşık hem de bu dersin amacını aşıyor. Onun yerine **aynı karar mantığını** izole, gözlemlenebilir, elle test edilebilir bir ortamda yeniden kuruyoruz. Bir paketi gerçekten ağdan yakalamak yerine, `Packet(src_ip="198.51.100.66", dst_ip="10.0.0.20", protocol="tcp", dst_port=22, flags="SYN")` diye bir satırla **temsil ediyoruz**.

---

## 2. Amaç ve hedef — bu proje hangi soruyu cevaplıyor?

Kitabın (Ch. 10 — Networks and Telecommunications, Firewall bölümü) anlattığı kavramlar **soyut**: "implicit deny", "stateful inspection", "DMZ", "flood guard" gibi terimler sayfada birer tanım olarak durur. Soru şu: **bunları birinin önünde nasıl "gösterirsin"?**

Bu projenin hedefi, her bir kavram için **tıklayınca sonucu değişen, somut bir deney** üretmek:

| Soyut kavram (kitapta) | Bu projede somut deney |
|---|---|
| "Packet filter sadece 5-tuple'a bakar" | Bir paket üret, kuralları `Rule.mismatches()` ile adım adım gör |
| "İlk eşleşen kural kazanır" | Kural sırasını değiştir, aynı paketin kararının değiştiğini gör |
| "Implicit deny: izin verilmeyen her şey kapalı" | Hiçbir kurala uymayan bir paket gönder, DENY gerekçesini oku |
| "Stateful inspection bağlantıyı hatırlar" | Stateful anahtarını aç/kapat, aynı dönüş paketinin kaderinin değiştiğini gör |
| "Flood guard taşkını keser ama DDoS'u kesemez" | Tek kaynaklı SYN seli ile çok kaynaklı DDoS'u yan yana karşılaştır |
| "DMZ / network separation" | DMZ'den veritabanına atılan paketin engellendiğini gör |

Yani hedef "bir firewall yazmak" değil — **firewall kavramlarını tartışılamaz, elle tutulur hâle getirmek.** Bu yüzden proje hem bir **kod** hem de bir **laboratuvar cihazı** gibi tasarlandı: her buton bir deney, her deneyin bir "neden böyle oldu" açıklaması var.

---

## 3. Genel mimari — "tek motor, üç önyüz" fikri

Projenin en önemli tasarım kararı şu: **karar verme mantığı tek bir yerde yaşıyor**, geri kalan her şey (web arayüzü, terminal, PCAP okuyucu) o tek mantığı farklı şekillerde göstermekten ibaret.

```text
                    ┌─────────────────────────┐
  Web arayüzü ───▶  │                         │
  (tarayıcı, JS)    │                         │
                    │   Firewall.evaluate()   │  ◀── TEK karar motoru
  Terminal   ───▶   │     (engine.py)         │      (minifirewall/engine.py)
  (cli.py)          │                         │
                    │                         │
  .pcap dosyası ──▶ │                         │
                    └─────────────────────────┘
                              │
                              ▼
                     Decision: ALLOW / DENY
                     + gerekçe + kural izi
```

Bunun pratik faydası: web arayüzünde gördüğün "ALLOW/DENY" kararı ile terminalde `python3 run.py trace ...` ile gördüğün karar **matematiksel olarak aynı fonksiyondan** çıkıyor. Biri "gösteriş", diğeri "okunabilirlik" içinmiş gibi görünse de ikisi de aynı gerçeği anlatıyor — bu da projenin güvenilirliğinin (ve sunumdaki en güçlü argümanlardan birinin) temeli.

### Dosyalar ne işe yarıyor?

```text
minifirewall/
├── packet.py      → Bir "paket" ne demek? (5-tuple + bayraklar + doğrulama)
├── rules.py       → Bir "kural" ne demek? + metin kural dilinin ayrıştırıcısı
├── engine.py       ★ KARAR MOTORU — flood → stateful → kurallar → politika
├── analysis.py    → Kuralları statik analiz eder (lint): çakışma, gölgelenme
├── export.py      → Kural listesini gerçek iptables komutlarına çevirir
├── scenarios.py   → 8 hazır senaryo (kural setleri, ağ tasarımları)
├── traffic.py     → Saldırı/trafik üreteçleri (port taraması, DDoS, vs.)
├── pcap.py        → Bağımlılıksız .pcap (Wireshark formatı) okuyucu/yazıcı
├── quiz.py        → Terminal tabanlı "ALLOW mı DENY mi?" quiz'i
├── cli.py         → Komut satırı arayüzü (demo, quiz, lint, trace, pcap...)
└── server.py      → HTTP sunucusu + JSON API (web arayüzünü besler)

web/               → Tarayıcı arayüzü: HTML + CSS + saf JavaScript (framework yok)
```

Okuma sırası önerim (aşağıdaki bölümlerde de bu sırayla anlatacağım): `packet.py` → `rules.py` → `engine.py` → (gerisi detaylar).

---

## 4. Bir "paket" nedir? (`packet.py`)

Gerçek bir ağ paketi onlarca alan içerir (checksum, TTL, sıra numarası...). Biz sadece firewall kararını etkileyen **5-6 alana** indirgiyoruz çünkü bir firewall da zaten sadece bunlara bakar:

| Alan | Örnek | Anlamı |
|---|---|---|
| `src_ip` | `198.51.100.66` | Paketi gönderen IP |
| `dst_ip` | `10.0.0.20` | Paketin gittiği IP |
| `protocol` | `tcp` / `udp` / `icmp` | Hangi protokol |
| `src_port` | `51234` | Gönderenin portu (TCP/UDP'de var, ICMP'de yok) |
| `dst_port` | `22` | Hedef servis portu (22 = SSH, 443 = HTTPS, 53 = DNS...) |
| `flags` | `SYN` | TCP bayrakları (bağlantı kurma/kapatma aşaması) |

Bu beşlisine literatürde **5-tuple** denir — "packet filtering" kavramının tam kalbi budur: filtre, paketin **içeriğini** değil, sadece bu zarftaki bilgiyi okur.

---

## 5. Bir "kural" nedir ve nasıl eşleşir? (`rules.py`)

Kurallar iptables'a benzeyen tek satırlık bir dille yazılır:

```text
ACTION PROTO KAYNAK SPORT HEDEF DPORT [flags=SYN] [# yorum]
```

Örnek: `allow tcp any any 10.0.0.10 443  # HTTPS herkese açık`

Bunu Türkçeye çevirirsek: *"Protokolü TCP olan, kaynağı her yerden, hedefi 10.0.0.10 ve hedef portu 443 olan paketlere izin ver."*

`any` kelimesi "fark etmez" demek; `10.0.0.0/24` bir alt ağ (CIDR) demek; `80,443` liste; `1024-65535` aralık demek.

**En kritik fonksiyon burada `Rule.mismatches(packet)`** ([rules.py:157](minifirewall/rules.py:157)). Mantığı çok basit ama projenin tüm doğruluğu buna dayanıyor:

1. Protokol kuralla uyuşuyor mu? Uyuşmuyorsa listeye bir "neden" ekle.
2. Kaynak IP, kuraldaki ağ aralığının içinde mi?
3. Hedef IP, kuraldaki ağ aralığının içinde mi?
4. (Sadece TCP/UDP'de) Kaynak port ve hedef port uyuyor mu?
5. Kuralda bayrak isteniyorsa (`flags=SYN`), paket bu bayrakların **hepsini** taşıyor mu?

Bu beş kontrolün **hepsi** geçerse (yani dönen liste **boşsa**) kural eşleşmiş sayılır. Tek bir alan bile uymazsa kural o paket için devre dışıdır. Bu "VE" mantığı (hepsi birden doğru olmalı) gerçek ACL'lerin de çalışma şeklidir.

> Neden bu fonksiyon "mismatches" (uymayanlar) döndürüyor, "matches" (bool) değil? Çünkü aynı fonksiyon hem karara hem de arayüzdeki "bu kural neden atlandı?" açıklamasına hizmet ediyor — "kaynak IP 198.51.100.66 kapsam dışı, hedef port 22 kapsam dışı" gibi cümleler doğrudan bu listeden geliyor. Tek bir fonksiyon, iki iş.

---

## 6. Karar motoru nasıl çalışıyor? (`engine.py` → `Firewall.evaluate()`)

Bu, projenin **beyni**. Bir paket geldiğinde şu sırayla kontrol edilir ([engine.py:159-284](minifirewall/engine.py:159)):

```text
Paket gelir
   │
   ▼
① Flood guard açık mı ve bu kaynak IP limiti aştı mı?  → evet: DENY (dur)
   │ hayır
   ▼
② Stateful açık mı ve bu paket bilinen bir oturumun parçası mı?  → evet: ALLOW (dur)
   │ hayır
   ▼
③ Kuralları yukarıdan aşağı sırayla dene (ilk eşleşen kazanır)
   │
   ├─ Eşleşen kural bulundu → kuralın action'ı (allow/deny) uygulanır
   │
   └─ Hiçbiri eşleşmedi → ④ varsayılan politika uygulanır (allow ya da deny)
   │
   ▼
Stateful açıksa ve sonuç ALLOW ise: bu akışı oturum tablosuna kaydet (120 sn)
```

Bunu adım adım, gerçek bir örnekle takip edelim — **Senaryo 3 (SSH bastion)** kullanılıyor, kurallardan biri `allow tcp 203.0.113.0/24 any 10.0.0.20 22`:

1. Paket: `198.51.100.66:51234 → 10.0.0.20:22 [SYN]`
2. **Flood guard** kapalı → atla.
3. **Stateful** kapalı → atla.
4. Kural listesine bakılır: `allow tcp 203.0.113.0/24 any 10.0.0.20 22` kuralı kaynak IP'yi kontrol eder — `198.51.100.66`, `203.0.113.0/24` aralığında **değil** → kural eşleşmedi, bir sonrakine geç.
5. Başka eşleşen kural yok.
6. **Varsayılan politika DENY** → sonuç: **DENY, "implicit deny"**.

Aynı paketi kaynak IP'yi `203.0.113.9` yaparak tekrar gönderirsen, 4. adımda kural eşleşir (bu IP aralığın içinde) → **ALLOW** döner. İşte "aynı port, farklı kaynak IP, farklı sonuç" dediğimiz şey tam olarak bu.

### Stateful inspection ayrıntısı

Stateful açıkken, bir paket **izin aldığında** motor onun hem gidiş hem **geri dönüş** yönünü bir oturum tablosuna yazar ([engine.py:277-281](minifirewall/engine.py:277)):

```text
1) 10.0.0.42:51515 → 93.184.216.34:443 [SYN]      kural izin verdi  → tabloya İKİ yön de yazılır
2) 93.184.216.34:443 → 10.0.0.42:51515 [SYN ACK]  kural listesinde böyle bir izin YOK
                                                   ama tabloda var → direkt ALLOW
```

Stateful **kapalıyken** aynı 2. paket kural listesine bakar, hiçbir kural böyle bir yöne izin vermediği için **DENY** döner. Bu, kitaptaki "basit packet filter hafızasızdır" cümlesinin birebir kanıtı.

### Flood guard ayrıntısı

Her kaynak IP için, son 1 saniyedeki paket zaman damgaları bir kuyrukta (deque) tutulur ([engine.py:295-312](minifirewall/engine.py:295)). Limit (varsayılan 30/sn) aşılırsa fazlası kesilir. **Önemli nokta:** limit **kaynak IP başınadır**. Yani:

- Tek bir IP'den gelen SYN seli → hızla limit aşılır → çoğu paket kesilir. ✅ Flood guard işe yarıyor.
- Yüzlerce **farklı sahte IP'den** gelen DDoS → her IP kendi başına limitin altında kalır → **hiçbiri kesilmez.** ❌ Flood guard bunu durduramaz.

Bu kasıtlı bir öğretim noktası: "hız sınırlama tek başına dağıtık saldırıyı çözmez" gerçeğini koda döküyor.

---

## 7. Kural analizi — lint (`analysis.py`)

Gerçek dünyada en sık yapılan hata şudur: geniş bir `allow any any` kuralını listenin **üstüne** koymak, altındaki daha dar bir `deny` kuralını tamamen anlamsız kılar (çünkü ilk eşleşen kazanır). `analysis.py` bunu otomatik tespit eder:

| Bulgu | Ne demek |
|---|---|
| `shadowed` (gölgelenmiş) | Bu kural üstündeki bir kural tarafından tamamen kapsanıyor → **hiçbir zaman çalışmaz**. Eylemler farklıysa gerçek güvenlik açığı. |
| `redundant` (gereksiz) | Üstteki kural zaten aynı işi (aynı action ile) yapıyor. |
| `broad` (çok geniş) | `any → any` gibi her şeye izin veren bir kural. |
| `overlap` (çakışma) | İki kural kısmen aynı paketleri kapsıyor ama farklı eylemde — sıra belirleyici. |

Bu, kitabın "rule-based management" / "kuralların doğru sıralanması" kavramına karşılık geliyor.

---

## 8. iptables'a çeviri (`export.py`)

Yazdığın soyut kural dili (`allow tcp any any 10.0.0.10 443`), gerçek bir Linux sunucusunda çalıştırılabilecek komuta çevrilir:

```bash
iptables -A FORWARD -p tcp -d 10.0.0.10/32 --dport 443 -m comment --comment "HTTPS" -j ACCEPT
```

Bu, projenin "soyut kavram" ile "gerçek dünya aracı" arasında köprü kurduğu yer — kitaptaki teorinin gerçek sistemlerde nasıl karşılık bulduğunu gösteriyor (çalıştırmak için değil, okumak/öğrenmek için).

---

## 9. Web arayüzü nasıl çalışıyor?

### 9.1 Teknik olarak ne oluyor?

`python3 run.py` çalıştırıldığında Python'un **kendi standart kütüphanesindeki** `http.server` modülü ([server.py](minifirewall/server.py)) `127.0.0.1:8080` adresinde bir sunucu açar. Tarayıcı bu adrese gidince `web/index.html` + `web/styles.css` + `web/app.js` dosyaları (düz HTML/CSS/JS — React yok, npm yok, build adımı yok) yüklenir.

Arayüzdeki her etkileşim (paket gönder, senaryo değiştir, kural ekle...) arka planda bir **HTTP isteği** olarak sunucuya gider, sunucu `Firewall.evaluate()`'i çağırır, JSON cevabı döner, JavaScript ekranı günceller:

```text
Tarayıcı (app.js)  --POST /api/packet-->  server.py  --çağırır-->  engine.py  --Decision-->  server.py  --JSON-->  app.js  --DOM günceller-->  Ekran
```

Önemli uç noktalar: `/api/packet` (tek paket gönder), `/api/burst` (saldırı senaryosu tetikle), `/api/rules` (kural listesini değiştir), `/api/state` (tüm durumu çek — arayüz her 1 sn'de bir bunu çağırıp kendini tazeler).

### 9.2 Ekrandaki bölümler ne işe yarar?

```text
┌──────────────────────────────────────────────────────────────────┐
│ Senaryo seçici │ ALLOW/DENY │ Stateful │ Flood guard │ Canlı trafik│ ← üst çubuk: global ayarlar
├───────────────┬────────────────────────────┬─────────────────────┤
│ PAKET ÜRETECİ │         TOPOLOJİ            │      KURALLAR       │
│ (elle paket   │ (paketler soldan sağa uçar, │ (sıralı liste,      │
│  kurup gönder)│  izin=yeşil, engel=kırmızı) │  tıkla=düzenle)      │
│ SALDIRI       │                              │                     │
│ BUTONLARI     │                              │                     │
├───────────────┴────────────────────────────┴─────────────────────┤
│              CANLI KARAR AKIŞI (her paketin ALLOW/DENY + gerekçesi)│
└────────────────────────────────────────────────────────────────────┘
```

- **Paket üreteci**: 5-tuple'ı elle doldurup tek bir paket gönderebildiğin form. "Bu spesifik durumda ne olur?" sorusunu test etmek için.
- **Saldırı butonları**: Arka planda yüzlerce paketi otomatik üretip gönderir (port taraması = tek IP'den tüm portlara tek tek paket; DDoS = yüzlerce farklı sahte IP'den aynı hedefe; vs.). `traffic.py` bu üreticileri barındırır.
- **Topoloji**: Kararın görselleştirilmiş hâli — paketin "uçtuğunu", izinliyse hedefe ulaştığını, engellendiyse firewall ikonunda "patladığını" gösteren bir canvas animasyonu.
- **Kural listesi**: Aynı anda hem kuralları görüp düzenleyebildiğin hem de her kuralın kaç kez eşleştiğini (hits) gördüğün panel. Lint uyarıları burada rozet olarak çıkar.
- **Kural izi**: Son gönderilen paket için, **her kuralın** neden eşleşip eşleşmediğinin (`mismatches()` çıktısının) tablo hâli — projenin "kapak altını açan" en öğretici parçası.
- **Canlı karar akışı**: Kronolojik log — her paketin ALLOW/DENY kararı ve gerekçesi.

---

## 10. Terminal nasıl çalışıyor? (`cli.py`)

Aynı motoru, görsel olmadan, düz metinle kullanmanın yolu:

```bash
python3 run.py demo              # 7 bölümlük hikayeli demo (tüm kavramları sırayla anlatır)
python3 run.py demo --step       # her bölümde Enter bekler (sunum için ideal)
python3 run.py trace --src X --dst Y --dport 22   # tek paketi kural kural izler
python3 run.py lint --scenario messy              # kural çakışması/gölgelenme analizi
python3 run.py quiz               # "ALLOW mı DENY mi?" interaktif test
python3 run.py pcap demo/capture.pcap             # gerçek bir .pcap dosyasını kurallardan geçirir
python3 run.py iptables --scenario web            # kuralların iptables karşılığını basar
```

`trace` komutu özellikle öğretici: web arayüzündeki "Kural izi" panelinin birebir terminal hâlidir — her kural için "atlandı, çünkü ..." ya da "EŞLEŞTİ" yazar.

---

## 11. Hazır senaryolar neden var? (`scenarios.py`)

Her senaryo, belirli bir öğretim noktasını izole eden **hazır bir kural seti + politika**:

| # | Senaryo | Ne öğretiyor |
|---|---|---|
| 1 | Açık firewall | Filtre olmayınca ne olur (kontrol grubu / baseline) |
| 2 | Web sunucusu | Temel ACL + implicit deny |
| 3 | SSH bastion | Aynı port, farklı kaynak IP → farklı sonuç (CIDR) |
| 4 | Katmanlı / DMZ | Network separation |
| 5 | Saldırı altında | Kademeli savunma |
| 6 | Stateful inspection | Dönüş paketi kural olmadan geçer |
| 7 | Flood guard | Sel ≠ DDoS |
| 8 | Hatalı kural sırası | "İlk eşleşen kazanır" tuzağı + lint |

Her senaryo, kitaptaki bir cümleyi doğrudan test edilebilir bir deneye çeviriyor — proje aslında "senaryoların toplamı" olarak düşünülebilir.

---

## 12. Nasıl test edilir?

### 12.1 Otomatik testler (asıl doğrulama)

```bash
python3 -m unittest discover -s tests -v
```

`tests/test_firewall.py` içinde **43 birim testi** var. Bunlar şunları kanıtlıyor (yani "bu proje çalışıyor" derken referans aldığın şey bu):

- Kural ayrıştırma doğru çalışıyor mu, hatalı kurallar (geçersiz IP, 70000 portu, ters aralık) reddediliyor mu?
- CIDR ve port aralıklarının **sınır değerleri** doğru mu (ör. `/24`'ün tam kenarındaki bir IP)?
- Protokol/bayrak eşleşmesi doğru mu?
- "İlk eşleşen kazanır" gerçekten ilk eşleşeni mi seçiyor?
- Implicit deny gerçekten hiçbir kural yokken devreye giriyor mu?
- Stateful: dönüş paketi gerçekten geçiyor mu, stateless modda gerçekten engelleniyor mu, **engellenen** bir paket yanlışlıkla oturum açıyor mu (açmamalı)?
- Flood guard: sahte saat ile kayan pencere doğru mu, DDoS gerçekten geçiyor mu (beklenen davranış bu)?
- Lint: gölgelenmiş kuralı doğru buluyor mu, 8 hazır senaryonun hiçbirinde yanlışlıkla gölgelenme yok mu?
- PCAP: bir dosya yazılıp tekrar okunduğunda aynı veriyi veriyor mu?

Test geçerse, motorun **mantığının** doğru olduğundan eminsin — bu, arayüzün "güzel görünmesinden" bağımsız bir garanti.

### 12.2 Elle / canlı test (davranışı gözle doğrulamak)

```bash
# 1) Bilinen bir paketin kararını elle doğrula
python3 run.py trace --scenario web --src 198.51.100.66 --dst 10.0.0.20 --dport 22
# Beklenti: DENY, çünkü senaryo "web"de SSH'e izin yok

# 2) Kural sırası tuzağını doğrula
python3 run.py lint --scenario messy
# Beklenti: "#2 ... asla çalışmaz" uyarısı çıkmalı

# 3) PCAP round-trip
python3 tools/make_pcap.py        # örnek dosyayı yeniden üret
python3 run.py pcap demo/capture.pcap --scenario web
```

### 12.3 Web arayüzünü test etmek

1. `python3 run.py` çalıştır, tarayıcı açılır.
2. Bir senaryo seç, bir saldırı butonuna bas, **Canlı karar akışı**'nda beklediğin sayıda ALLOW/DENY görüyor musun kontrol et.
3. **Kural izi** panelinde gösterilen gerekçenin, az önce `rules.py`'de okuduğun `mismatches()` mantığıyla tutarlı olduğunu doğrula.
4. Tarayıcı konsolunda (F12) kırmızı hata olmadığından emin ol.

---

## 13. Projenin dürüst sınırları — bunları bilmek önemli

Bir sunumda/ödevde "bunu biliyorum ama kapsam dışı bıraktım" demek, bilmemekten çok daha güçlü bir izlenim bırakır:

- **Gerçek paket yakalamıyor.** Paketler Python nesnesi olarak üretiliyor; işletim sistemi seviyesinde ağ kartına dokunulmuyor. (PCAP desteği gerçek yakalama dosyalarını *okuyabildiği* için bu farkı kısmen kapatıyor.)
- **Uygulama katmanı yok.** Motor sadece L3/L4'e (IP, port, protokol, bayrak) bakıyor, paketin **içeriğini** okumuyor. Bu yüzden port 53/UDP açıksa, içinde DNS tüneli ile veri kaçırılsa bile motor bunu **göremez** — gerçek çözüm kitaptaki **application proxy firewall** kavramı, bu proje onu modellemiyor.
- **Flood guard kaynak IP başınadır** → dağıtık (DDoS) saldırıyı durduramaz (bilinçli olarak gösterilen bir sınır, bkz. Bölüm 6).
- **TCP durum makinesi yok.** Stateful tablo sadece "bu akışa daha önce izin verildi mi" diye bakar; SYN/ACK sırasını, sekans numaralarını, FIN/RST ile düzgün kapanışı takip etmez — sadece 120 saniyelik bir zaman aşımı var.
- **Parçalama (fragmentation), NAT, çoklu arayüz** modellenmemiştir.

---

## 14. Özet — tek paragrafta

Bu proje, bir firewall'un "paketi görüp ALLOW/DENY kararı verme" mantığını (`Firewall.evaluate()`) saf Python'da, dış bağımlılık olmadan yeniden kurar; bu **tek motoru** bir web arayüzü, bir terminal arayüzü ve bir PCAP okuyucu üzerinden **üç farklı şekilde** gözlemlenebilir kılar; kitaptaki implicit deny, stateful inspection, flood guard ve DMZ gibi soyut kavramların her birini, tek bir düğmeye basınca sonucu değişen somut bir deneye dönüştürür; ve 43 birim testiyle bu mantığın sınır değerlerde bile doğru çalıştığını kanıtlar.

---

*İlgili dosyalar: [README.md](README.md) (teknik referans, kural dili, API), [SUNUM_AKISI.md](SUNUM_AKISI.md) (15-20 dk sunum provası).*
